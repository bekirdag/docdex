"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const { determineLocalInstallerOutcome } = require("../lib/install");

function createMockFs({ existingPaths = [], filesByPath = {}, readFileErrorByPath = {} } = {}) {
  const existing = new Set(existingPaths);
  const files = new Map(Object.entries(filesByPath));
  const readErrors = new Map(Object.entries(readFileErrorByPath));

  return {
    existsSync: (filePath) => existing.has(filePath) || files.has(filePath),
    promises: {
      readFile: async (filePath) => {
        if (readErrors.has(filePath)) throw readErrors.get(filePath);
        if (!files.has(filePath)) {
          const err = new Error(`ENOENT: no such file or directory, open '${filePath}'`);
          err.code = "ENOENT";
          throw err;
        }
        return files.get(filePath);
      }
    }
  };
}

function validInstallMetadata({ platformKey, version, binarySha256 }) {
  const binaryPath = path.posix.join("/dist", platformKey, "docdexd");
  return {
    schemaVersion: 2,
    installedVersion: version,
    expectedVersion: version,
    platformKey,
    targetTriple: "x86_64-unknown-linux-gnu",
    binaryPath,
    binaryHash: binarySha256,
    provenance: {
      repoSlug: "owner/repo",
      releaseTag: `v${version}`,
      releaseId: null,
      assetName: null,
      assetUrl: null,
      assetSha256: null,
      source: "test"
    },
    installedAt: "2025-01-01T00:00:00.000Z",
    lastVerifiedAt: "2025-01-01T00:00:00.000Z"
  };
}

test("decision engine: missing binary => install (binary_missing)", async () => {
  const platformKey = "linux-x64-gnu";
  const distDir = path.posix.join("/dist", platformKey);

  const fsModule = createMockFs();
  const sha256FileFn = async () => {
    throw new Error("unexpected sha256");
  };

  const outcome = await determineLocalInstallerOutcome({
    fsModule,
    pathModule: path.posix,
    distDir,
    platformKey,
    expectedVersion: "0.1.0",
    isWin32: false,
    sha256FileFn
  });

  assert.equal(outcome.outcome, "install");
  assert.equal(outcome.reason, "binary_missing");
  assert.equal(outcome.plan, "upgrade");
  assert.equal(outcome.installedVersion, null);
});

test("decision engine: metadata missing => reinstall_unknown (metadata_missing)", async () => {
  const platformKey = "linux-x64-gnu";
  const distDir = path.posix.join("/dist", platformKey);
  const binaryPath = path.posix.join(distDir, "docdexd");

  const fsModule = createMockFs({ existingPaths: [binaryPath] });
  const sha256FileFn = async () => {
    throw new Error("unexpected sha256");
  };

  const outcome = await determineLocalInstallerOutcome({
    fsModule,
    pathModule: path.posix,
    distDir,
    platformKey,
    expectedVersion: "0.1.0",
    isWin32: false,
    sha256FileFn
  });

  assert.equal(outcome.outcome, "reinstall_unknown");
  assert.equal(outcome.reason, "metadata_missing");
  assert.equal(outcome.plan, "repair");
  assert.equal(outcome.integrityResult, null);
});

test("decision engine: metadata invalid => reinstall_unknown (metadata_invalid)", async () => {
  const platformKey = "linux-x64-gnu";
  const distDir = path.posix.join("/dist", platformKey);
  const binaryPath = path.posix.join(distDir, "docdexd");
  const metadataPath = path.posix.join(distDir, "docdexd-install.json");

  const fsModule = createMockFs({
    existingPaths: [binaryPath],
    filesByPath: {
      [metadataPath]: JSON.stringify({ schemaVersion: 2 }, null, 2)
    }
  });

  const outcome = await determineLocalInstallerOutcome({
    fsModule,
    pathModule: path.posix,
    distDir,
    platformKey,
    expectedVersion: "0.1.0",
    isWin32: false,
    sha256FileFn: async () => {
      throw new Error("unexpected sha256");
    }
  });

  assert.equal(outcome.outcome, "reinstall_unknown");
  assert.equal(outcome.reason, "metadata_invalid");
  assert.equal(outcome.plan, "repair");
});

test("decision engine: platform mismatch => reinstall_unknown (platform_mismatch)", async () => {
  const platformKey = "linux-x64-gnu";
  const distDir = path.posix.join("/dist", platformKey);
  const binaryPath = path.posix.join(distDir, "docdexd");
  const metadataPath = path.posix.join(distDir, "docdexd-install.json");

  const fsModule = createMockFs({
    existingPaths: [binaryPath],
    filesByPath: {
      [metadataPath]: JSON.stringify(
        validInstallMetadata({ platformKey: "darwin-x64", version: "0.1.0", binarySha256: "a".repeat(64) }),
        null,
        2
      )
    }
  });

  const outcome = await determineLocalInstallerOutcome({
    fsModule,
    pathModule: path.posix,
    distDir,
    platformKey,
    expectedVersion: "0.1.0",
    isWin32: false,
    sha256FileFn: async () => {
      throw new Error("unexpected sha256");
    }
  });

  assert.equal(outcome.outcome, "reinstall_unknown");
  assert.equal(outcome.reason, "platform_mismatch");
  assert.equal(outcome.plan, "repair");
  assert.equal(outcome.installedVersion, "0.1.0");
});

test("decision engine: version mismatch => upgrade (version_mismatch)", async () => {
  const platformKey = "linux-x64-gnu";
  const distDir = path.posix.join("/dist", platformKey);
  const binaryPath = path.posix.join(distDir, "docdexd");
  const metadataPath = path.posix.join(distDir, "docdexd-install.json");

  const fsModule = createMockFs({
    existingPaths: [binaryPath],
    filesByPath: {
      [metadataPath]: JSON.stringify(
        validInstallMetadata({ platformKey, version: "0.0.9", binarySha256: "a".repeat(64) }),
        null,
        2
      )
    }
  });

  const outcome = await determineLocalInstallerOutcome({
    fsModule,
    pathModule: path.posix,
    distDir,
    platformKey,
    expectedVersion: "0.1.0",
    isWin32: false,
    sha256FileFn: async () => {
      throw new Error("unexpected sha256");
    }
  });

  assert.equal(outcome.outcome, "upgrade");
  assert.equal(outcome.reason, "version_mismatch");
  assert.equal(outcome.plan, "upgrade");
  assert.equal(outcome.installedVersion, "0.0.9");
});

<<<<<<< HEAD
test("decision engine: version mismatch (higher installed) => update plan downgrade", async () => {
=======
test("decision engine: version mismatch => downgrade (version_mismatch)", async () => {
>>>>>>> mcoda/task/ops-01-us-06-t40
  const platformKey = "linux-x64-gnu";
  const distDir = path.posix.join("/dist", platformKey);
  const binaryPath = path.posix.join(distDir, "docdexd");
  const metadataPath = path.posix.join(distDir, "docdexd-install.json");

  const fsModule = createMockFs({
    existingPaths: [binaryPath],
    filesByPath: {
      [metadataPath]: JSON.stringify(
        validInstallMetadata({ platformKey, version: "0.2.0", binarySha256: "a".repeat(64) }),
        null,
        2
      )
    }
  });

  const outcome = await determineLocalInstallerOutcome({
    fsModule,
    pathModule: path.posix,
    distDir,
    platformKey,
    expectedVersion: "0.1.0",
    isWin32: false,
    sha256FileFn: async () => {
      throw new Error("unexpected sha256");
    }
  });

<<<<<<< HEAD
  assert.equal(outcome.outcome, "update");
  assert.equal(outcome.reason, "version_mismatch");
  assert.equal(outcome.plan, "downgrade");
=======
  assert.equal(outcome.outcome, "downgrade");
  assert.equal(outcome.reason, "version_mismatch");
>>>>>>> mcoda/task/ops-01-us-06-t40
  assert.equal(outcome.installedVersion, "0.2.0");
});

test("decision engine: binary hash mismatch => repair (binary_integrity_mismatch)", async () => {
  const platformKey = "linux-x64-gnu";
  const distDir = path.posix.join("/dist", platformKey);
  const binaryPath = path.posix.join(distDir, "docdexd");
  const metadataPath = path.posix.join(distDir, "docdexd-install.json");

  const fsModule = createMockFs({
    existingPaths: [binaryPath],
    filesByPath: {
      [metadataPath]: JSON.stringify(
        validInstallMetadata({ platformKey, version: "0.1.0", binarySha256: "a".repeat(64) }),
        null,
        2
      )
    }
  });

  let shaCalls = 0;
  const outcome = await determineLocalInstallerOutcome({
    fsModule,
    pathModule: path.posix,
    distDir,
    platformKey,
    expectedVersion: "0.1.0",
    isWin32: false,
    sha256FileFn: async (filePath) => {
      shaCalls += 1;
      assert.equal(filePath, binaryPath);
      return "b".repeat(64);
    }
  });

  assert.equal(outcome.outcome, "repair");
  assert.equal(outcome.reason, "binary_integrity_mismatch");
  assert.equal(outcome.plan, "repair");
  assert.equal(outcome.integrityResult.status, "mismatch");
  assert.equal(outcome.integrityResult.reason, "hash_mismatch");
  assert.equal(shaCalls, 1);
});

test("decision engine: verified => no-op (verified)", async () => {
  const platformKey = "linux-x64-gnu";
  const distDir = path.posix.join("/dist", platformKey);
  const binaryPath = path.posix.join(distDir, "docdexd");
  const metadataPath = path.posix.join(distDir, "docdexd-install.json");

  const fsModule = createMockFs({
    existingPaths: [binaryPath],
    filesByPath: {
      [metadataPath]: JSON.stringify(
        validInstallMetadata({ platformKey, version: "0.1.0", binarySha256: "a".repeat(64) }),
        null,
        2
      )
    }
  });

  let shaCalls = 0;
  const outcome = await determineLocalInstallerOutcome({
    fsModule,
    pathModule: path.posix,
    distDir,
    platformKey,
    expectedVersion: "0.1.0",
    isWin32: false,
    sha256FileFn: async (filePath) => {
      shaCalls += 1;
      assert.equal(filePath, binaryPath);
      return "a".repeat(64);
    }
  });

  assert.equal(outcome.outcome, "no-op");
  assert.equal(outcome.reason, "verified");
  assert.equal(outcome.plan, "no-op");
  assert.equal(outcome.integrityResult.status, "verified_ok");
  assert.equal(outcome.integrityResult.reason, "hash_match");
  assert.equal(outcome.installedVersion, "0.1.0");
  assert.equal(shaCalls, 1);
});

test("decision engine: integrity check throws => reinstall_unknown (integrity_unverifiable)", async () => {
  const platformKey = "linux-x64-gnu";
  const distDir = path.posix.join("/dist", platformKey);
  const binaryPath = path.posix.join(distDir, "docdexd");
  const metadataPath = path.posix.join(distDir, "docdexd-install.json");

  const fsModule = createMockFs({
    existingPaths: [binaryPath],
    filesByPath: {
      [metadataPath]: JSON.stringify(
        validInstallMetadata({ platformKey, version: "0.1.0", binarySha256: "a".repeat(64) }),
        null,
        2
      )
    }
  });

  let shaCalls = 0;
  const outcome = await determineLocalInstallerOutcome({
    fsModule,
    pathModule: path.posix,
    distDir,
    platformKey,
    expectedVersion: "0.1.0",
    isWin32: false,
    sha256FileFn: async (filePath) => {
      shaCalls += 1;
      assert.equal(filePath, binaryPath);
      throw new Error("EACCES: permission denied");
    }
  });

  assert.equal(outcome.outcome, "reinstall_unknown");
  assert.equal(outcome.reason, "integrity_unverifiable");
  assert.equal(outcome.plan, "repair");
  assert.equal(outcome.installedVersion, "0.1.0");
  assert.equal(outcome.integrityResult.status, "unverifiable");
  assert.equal(outcome.integrityResult.reason, "unreadable");
  assert.equal(shaCalls, 1);
});
