"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const {
  generateReleaseManifest,
  DEFAULT_TARGETS
} = require("../../scripts/generate_release_manifest.cjs");

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function mkTmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "docdex-release-manifest-"));
}

test("generateReleaseManifest: emits targets mapping with sha256 and validates checksums", () => {
  const dir = mkTmpDir();
  const outPath = path.join(dir, "docdexd-manifest.json");

  const expectedByTriple = new Map();

  for (const entry of DEFAULT_TARGETS) {
    const tarName = `${entry.archiveBase}.tar.gz`;
    const tarPath = path.join(dir, tarName);
    const payload = Buffer.from(`fake-archive:${tarName}\n`, "utf8");
    fs.writeFileSync(tarPath, payload);

    const tarSha = sha256(payload);
    expectedByTriple.set(entry.targetTriple, { tarName, tarSha });

    const shaFilePath = `${tarPath}.sha256`;
    fs.writeFileSync(shaFilePath, `${tarSha}  ${tarName}\n`, "utf8");
  }

  const now = new Date("2025-01-01T00:00:00.000Z");
  const result = generateReleaseManifest({
    assetsDir: dir,
    outPath,
    tag: "v0.0.0",
    repo: "owner/repo",
    now
  });

  assert.equal(result.manifestPath, outPath);
  assert.equal(result.sha256Path, `${outPath}.sha256`);
  assert.ok(fs.existsSync(outPath));
  assert.ok(fs.existsSync(`${outPath}.sha256`));
  assert.ok(fs.existsSync(result.checksumsPath));
  assert.ok(fs.existsSync(result.checksumsTxtPath));
  assert.equal(
    fs.readFileSync(result.checksumsPath, "utf8"),
    fs.readFileSync(result.checksumsTxtPath, "utf8")
  );

  const manifest = JSON.parse(fs.readFileSync(outPath, "utf8"));
  assert.equal(manifest.manifestVersion, 1);
  assert.equal(manifest.repo, "owner/repo");
  assert.equal(manifest.tag, "v0.0.0");
  assert.equal(manifest.version, "0.0.0");
  assert.equal(manifest.generatedAt, now.toISOString());

  const triples = Object.keys(manifest.targets).sort();
  assert.deepEqual(
    triples,
    DEFAULT_TARGETS.map((t) => t.targetTriple).slice().sort()
  );

  for (const triple of triples) {
    const expected = expectedByTriple.get(triple);
    assert.ok(expected, `missing expected triple ${triple}`);
    const targetEntry = manifest.targets[triple];
    assert.equal(targetEntry.asset.name, expected.tarName);
    assert.equal(targetEntry.integrity.sha256, expected.tarSha);
  }

  assert.ok(Array.isArray(manifest.publishedAssets));
  assert.equal(manifest.publishedAssets.length, DEFAULT_TARGETS.length * 2);
  for (const entry of manifest.publishedAssets) {
    assert.equal(typeof entry.name, "string");
    assert.match(entry.sha256, /^[0-9a-f]{64}$/);
  }

  const manifestShaLine = fs.readFileSync(`${outPath}.sha256`, "utf8").trim();
  assert.match(manifestShaLine, /^[0-9a-f]{64}\s+docdexd-manifest\.json$/);
  assert.equal(manifestShaLine.split(/\s+/)[0], sha256(fs.readFileSync(outPath)));

  const checksums = fs.readFileSync(result.checksumsPath, "utf8");
  for (const { tarName, tarSha } of expectedByTriple.values()) {
    assert.match(checksums, new RegExp(`^${tarSha}\\s+${tarName}$`, "m"));
  }
  const manifestSha = sha256(fs.readFileSync(outPath));
  assert.match(checksums, new RegExp(`^${manifestSha}\\s+docdexd-manifest\\.json$`, "m"));
  const manifestShaFileSha = sha256(fs.readFileSync(`${outPath}.sha256`));
  assert.match(checksums, new RegExp(`^${manifestShaFileSha}\\s+docdexd-manifest\\.json\\.sha256$`, "m"));
});

test("generateReleaseManifest: signs integrity metadata when private key is provided", () => {
  const dir = mkTmpDir();
  const outPath = path.join(dir, "docdexd-manifest.json");

  const originalKey = process.env.DOCDEX_RELEASE_SIGNING_PRIVATE_KEY;
  try {
    const { generateKeyPairSync, verify } = require("node:crypto");
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    process.env.DOCDEX_RELEASE_SIGNING_PRIVATE_KEY = privateKey.export({ format: "pem", type: "pkcs8" });

    const entry = DEFAULT_TARGETS[0];
    const tarName = `${entry.archiveBase}.tar.gz`;
    const tarPath = path.join(dir, tarName);
    const payload = Buffer.from("payload", "utf8");
    fs.writeFileSync(tarPath, payload);
    fs.writeFileSync(`${tarPath}.sha256`, `${sha256(payload)}  ${tarName}\n`, "utf8");

    const result = generateReleaseManifest({
      assetsDir: dir,
      outPath,
      targets: [entry]
    });

    assert.ok(fs.existsSync(`${outPath}.sig`));
    assert.ok(fs.existsSync(`${result.checksumsPath}.sig`));
    assert.ok(fs.existsSync(`${result.checksumsTxtPath}.sig`));

    const sigB64 = fs.readFileSync(`${outPath}.sig`, "utf8").trim();
    const ok = verify(
      null,
      fs.readFileSync(outPath),
      publicKey,
      Buffer.from(sigB64, "base64")
    );
    assert.equal(ok, true);
  } finally {
    if (originalKey === undefined) delete process.env.DOCDEX_RELEASE_SIGNING_PRIVATE_KEY;
    else process.env.DOCDEX_RELEASE_SIGNING_PRIVATE_KEY = originalKey;
  }
});

test("generateReleaseManifest: missing assets fails with stable exitCode", () => {
  const dir = mkTmpDir();
  const outPath = path.join(dir, "docdexd-manifest.json");

  const entry = DEFAULT_TARGETS[0];
  const tarName = `${entry.archiveBase}.tar.gz`;
  fs.writeFileSync(path.join(dir, tarName), Buffer.from("x", "utf8"));
  fs.writeFileSync(path.join(dir, `${tarName}.sha256`), `${sha256(Buffer.from("x"))}  ${tarName}\n`, "utf8");

  assert.throws(
    () => generateReleaseManifest({ assetsDir: dir, outPath }),
    (err) => {
      assert.equal(err.exitCode, 3);
      assert.match(err.message, /^Missing expected release assets:/);
      return true;
    }
  );
});

test("generateReleaseManifest: checksum mismatch fails with stable exitCode", () => {
  const dir = mkTmpDir();
  const outPath = path.join(dir, "docdexd-manifest.json");

  const entry = DEFAULT_TARGETS[0];
  const tarName = `${entry.archiveBase}.tar.gz`;
  const tarPath = path.join(dir, tarName);
  fs.writeFileSync(tarPath, Buffer.from("payload", "utf8"));

  const declared = sha256(Buffer.from("different", "utf8"));
  fs.writeFileSync(path.join(dir, `${tarName}.sha256`), `${declared}  ${tarName}\n`, "utf8");

  assert.throws(
    () =>
      generateReleaseManifest({
        assetsDir: dir,
        outPath,
        targets: [entry]
      }),
    (err) => {
      assert.equal(err.exitCode, 4);
      assert.match(err.message, new RegExp(`^Checksum mismatch for ${tarName}: declared sha256=`));
      return true;
    }
  );
});

test("generateReleaseManifest: unparseable checksum file fails with stable exitCode", () => {
  const dir = mkTmpDir();
  const outPath = path.join(dir, "docdexd-manifest.json");

  const entry = DEFAULT_TARGETS[0];
  const tarName = `${entry.archiveBase}.tar.gz`;
  const tarPath = path.join(dir, tarName);
  fs.writeFileSync(tarPath, Buffer.from("payload", "utf8"));

  fs.writeFileSync(path.join(dir, `${tarName}.sha256`), `not a checksum file\n`, "utf8");

  assert.throws(
    () =>
      generateReleaseManifest({
        assetsDir: dir,
        outPath,
        targets: [entry]
      }),
    (err) => {
      assert.equal(err.exitCode, 4);
      assert.equal(err.message, `Could not parse SHA-256 file: ${tarName}.sha256`);
      return true;
    }
  );
});
