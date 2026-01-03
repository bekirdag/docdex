"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { PLATFORM_MATRIX } = require("../lib/platform_matrix");
const { collectReleaseAssetIssues } = require("../../scripts/validate_release_assets.cjs");

function mkTmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "docdex-release-assets-"));
}

function touch(dir, name) {
  fs.writeFileSync(path.join(dir, name), "");
}

test("collectReleaseAssetIssues: ok when all expected assets exist", () => {
  const dir = mkTmpDir();
  for (const entry of PLATFORM_MATRIX.filter((e) => e.published)) {
    touch(dir, `docdexd-${entry.platformKey}.tar.gz`);
  }

  const result = collectReleaseAssetIssues({ assetsDir: dir });
  assert.equal(result.ok, true);
  assert.equal(result.missing.length, 0);
  assert.equal(result.nonCanonical.length, 0);
  assert.equal(result.duplicateTriples.length, 0);
  assert.equal(result.duplicateAssets.length, 0);
});

test("collectReleaseAssetIssues: reports missing and non-canonical assets", () => {
  const dir = mkTmpDir();
  const [first] = PLATFORM_MATRIX.filter((e) => e.published);
  touch(dir, `docdexd-${first.platformKey}.tar.gz`);
  touch(dir, "docdexd-linux-x64-gnu-alt.tar.gz");

  const result = collectReleaseAssetIssues({ assetsDir: dir });
  assert.equal(result.ok, false);
  assert.ok(result.missing.length > 0);
  assert.equal(result.nonCanonical.length, 1);
  assert.match(result.nonCanonical[0].name, /docdexd-linux-x64-gnu-alt\.tar\.gz/);
});

test("collectReleaseAssetIssues: reports duplicate target triples", () => {
  const dir = mkTmpDir();
  const baseEntry = PLATFORM_MATRIX.find((e) => e.published);
  const altEntry = {
    ...baseEntry,
    platformKey: `${baseEntry.platformKey}-alt`
  };
  const customMatrix = [baseEntry, altEntry];

  touch(dir, `docdexd-${baseEntry.platformKey}.tar.gz`);
  touch(dir, `docdexd-${altEntry.platformKey}.tar.gz`);

  const result = collectReleaseAssetIssues({ assetsDir: dir, platformMatrix: customMatrix });
  assert.equal(result.ok, false);
  assert.equal(result.missing.length, 0);
  assert.equal(result.nonCanonical.length, 0);
  assert.equal(result.duplicateTriples.length, 1);
  assert.equal(result.duplicateAssets.length, 1);
});
