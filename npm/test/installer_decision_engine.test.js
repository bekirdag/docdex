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
<<<<<<< HEAD
  const binaryPath = path.posix.join("/dist", platformKey, "docdexd");
=======
  const archiveName = `docdexd-${platformKey}.tar.gz`;
  const archiveSha256 = "c".repeat(64);
>>>>>>> mcoda/task/ops-01-us-06-t03
  return {
<<<<<<< HEAD
    schemaVersion: 2,
    installedVersion: version,
    expectedVersion: version,
=======
    schemaVersion: 1,
    installedAt: "2025-01-01T00:00:00.000Z",
    version,
    expectedVersion: version,
    installedVersion: version,
    releaseTag: `v${version}`,
    repoSlug: "owner/repo",
>>>>>>> mcoda/task/ops-01-us-03-t43
    platformKey,
    targetTriple: "x86_64-unknown-linux-gnu",
<<<<<<< HEAD
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
=======
    binary: {
      filename: "docdexd",
      sha256: binarySha256
    },
    archive: {
<<<<<<< HEAD
      name: archiveName,
      sha256: archiveSha256,
      source: "manifest:docdex-release-manifest.json",
      downloadUrl: `https://example.test/releases/download/v${version}/${archiveName}`
=======
      name: "docdexd-linux-x64-gnu.tar.gz",
      tag: `v${version}`,
      sha256: "b".repeat(64),
      source: "fallback",
      downloadUrl: `https://example.test/v${version}/docdexd-linux-x64-gnu.tar.gz`
>>>>>>> mcoda/task/ops-01-us-03-t43
    }
>>>>>>> mcoda/task/ops-01-us-06-t03
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

<<<<<<< HEAD
  assert.equal(outcome.outcome, "install");
=======
  assert.equal(outcome.outcome, "update");
  assert.equal(outcome.action, "upgrade");
>>>>>>> mcoda/task/ops-01-us-06-t02
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
  assert.equal(outcome.action, "repair");
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
  assert.equal(outcome.action, "repair");
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
  assert.equal(outcome.action, "repair");
  assert.equal(outcome.reason, "platform_mismatch");
  assert.equal(outcome.plan, "repair");
  assert.equal(outcome.installedVersion, "0.1.0");
});

<<<<<<< HEAD
test("decision engine: version mismatch => upgrade (version_mismatch)", async () => {
=======
test("decision engine: target triple mismatch => reinstall_unknown (platform_mismatch)", async () => {
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
    expectedTargetTriple: "aarch64-unknown-linux-gnu",
    isWin32: false,
    sha256FileFn: async () => {
      shaCalls += 1;
      throw new Error("unexpected sha256");
    }
  });

  assert.equal(outcome.outcome, "reinstall_unknown");
  assert.equal(outcome.reason, "platform_mismatch");
  assert.equal(outcome.installedVersion, "0.1.0");
  assert.equal(outcome.integrityResult, null);
  assert.equal(shaCalls, 0);
});

test("decision engine: version mismatch => update (version_mismatch)", async () => {
>>>>>>> mcoda/task/ops-01-us-01-t13
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
<<<<<<< HEAD
<<<<<<< HEAD
test("decision engine: version mismatch (higher installed) => update plan downgrade", async () => {
=======
test("decision engine: version mismatch => downgrade (version_mismatch)", async () => {
>>>>>>> mcoda/task/ops-01-us-06-t40
=======
test("decision engine: reported version mismatch => update (reported_version_mismatch)", async () => {
>>>>>>> mcoda/task/ops-01-us-03-t37
  const platformKey = "linux-x64-gnu";
  const distDir = path.posix.join("/dist", platformKey);
  const binaryPath = path.posix.join(distDir, "docdexd");
  const metadataPath = path.posix.join(distDir, "docdexd-install.json");
<<<<<<< HEAD
=======
  const sha = "a".repeat(64);
>>>>>>> mcoda/task/ops-01-us-03-t37

  const fsModule = createMockFs({
    existingPaths: [binaryPath],
    filesByPath: {
      [metadataPath]: JSON.stringify(
<<<<<<< HEAD
        validInstallMetadata({ platformKey, version: "0.2.0", binarySha256: "a".repeat(64) }),
=======
        validInstallMetadata({ platformKey, version: "0.1.0", binarySha256: sha }),
>>>>>>> mcoda/task/ops-01-us-03-t37
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
<<<<<<< HEAD
    sha256FileFn: async () => {
      throw new Error("unexpected sha256");
    }
  });

<<<<<<< HEAD
  assert.equal(outcome.outcome, "update");
  assert.equal(outcome.action, "upgrade");
  assert.equal(outcome.reason, "version_mismatch");
  assert.equal(outcome.plan, "downgrade");
=======
  assert.equal(outcome.outcome, "downgrade");
  assert.equal(outcome.reason, "version_mismatch");
>>>>>>> mcoda/task/ops-01-us-06-t40
  assert.equal(outcome.installedVersion, "0.2.0");
});

test("decision engine: downgrade when expected version is lower", async () => {
=======
test("decision engine: detected version mismatch => update (version_mismatch)", async () => {
>>>>>>> mcoda/task/ops-01-us-03-t45
  const platformKey = "linux-x64-gnu";
  const distDir = path.posix.join("/dist", platformKey);
  const binaryPath = path.posix.join(distDir, "docdexd");
  const metadataPath = path.posix.join(distDir, "docdexd-install.json");

  const fsModule = createMockFs({
    existingPaths: [binaryPath],
    filesByPath: {
      [metadataPath]: JSON.stringify(
<<<<<<< HEAD
        validInstallMetadata({ platformKey, version: "0.1.1", binarySha256: "a".repeat(64) }),
=======
        validInstallMetadata({ platformKey, version: "0.1.0", binarySha256: "a".repeat(64) }),
>>>>>>> mcoda/task/ops-01-us-03-t45
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
<<<<<<< HEAD
    }
  });

  assert.equal(outcome.outcome, "update");
  assert.equal(outcome.action, "downgrade");
  assert.equal(outcome.reason, "version_mismatch");
  assert.equal(outcome.installedVersion, "0.1.1");
=======
    sha256FileFn: async () => sha,
    detectInstalledBinaryVersionFn: async () => ({ version: "0.0.9", error: null })
  });

  assert.equal(outcome.outcome, "update");
  assert.equal(outcome.reason, "reported_version_mismatch");
  assert.equal(outcome.reportedVersion, "0.0.9");
>>>>>>> mcoda/task/ops-01-us-03-t37
=======
    },
    detectInstalledVersionFn: async () => ({ version: "0.0.9" })
  });

  assert.equal(outcome.outcome, "update");
  assert.equal(outcome.reason, "version_mismatch");
  assert.equal(outcome.detectedVersion, "0.0.9");
>>>>>>> mcoda/task/ops-01-us-03-t45
});

test("decision engine: binary hash mismatch => repair (binary_integrity_mismatch)", async () => {
  const platformKey = "linux-x64-gnu";
  const distDir = path.posix.join("/dist", platformKey);
  const binaryPath = path.posix.join(distDir, "docdexd");
  const metadataPath = path.posix.join(distDir, "docdexd-install.json");
  const expectedArchiveName = `docdexd-${platformKey}.tar.gz`;
  const expectedArchiveSha256 = "c".repeat(64);

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
    expectedArchiveName,
    expectedArchiveSha256,
    expectedArchiveSource: "manifest:docdex-release-manifest.json",
    sha256FileFn: async (filePath) => {
      shaCalls += 1;
      assert.equal(filePath, binaryPath);
      return "b".repeat(64);
    }
  });

  assert.equal(outcome.outcome, "repair");
  assert.equal(outcome.action, "repair");
  assert.equal(outcome.reason, "binary_integrity_mismatch");
  assert.equal(outcome.plan, "repair");
  assert.equal(outcome.integrityResult.status, "mismatch");
  assert.equal(outcome.integrityResult.reason, "hash_mismatch");
  assert.equal(shaCalls, 1);
});

test("decision engine: non-executable binary => repair (binary_not_executable)", async () => {
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
  fsModule.constants = { X_OK: 1 };
  fsModule.statSync = () => ({ isFile: () => true });
  fsModule.accessSync = (filePath) => {
    assert.equal(filePath, binaryPath);
    const err = new Error("EACCES: permission denied");
    err.code = "EACCES";
    throw err;
  };

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

  assert.equal(outcome.outcome, "repair");
  assert.equal(outcome.reason, "binary_not_executable");
  assert.equal(outcome.integrityResult, null);
});

test("decision engine: verified => no-op (verified)", async () => {
  const platformKey = "linux-x64-gnu";
  const distDir = path.posix.join("/dist", platformKey);
  const binaryPath = path.posix.join(distDir, "docdexd");
  const metadataPath = path.posix.join(distDir, "docdexd-install.json");
  const expectedArchiveName = `docdexd-${platformKey}.tar.gz`;
  const expectedArchiveSha256 = "c".repeat(64);

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
    expectedArchiveName,
    expectedArchiveSha256,
    expectedArchiveSource: "manifest:docdex-release-manifest.json",
    sha256FileFn: async (filePath) => {
      shaCalls += 1;
      assert.equal(filePath, binaryPath);
      return "a".repeat(64);
    }
  });

  assert.equal(outcome.outcome, "no-op");
  assert.equal(outcome.action, "no-op");
  assert.equal(outcome.reason, "verified");
  assert.equal(outcome.plan, "no-op");
  assert.equal(outcome.integrityResult.status, "verified_ok");
  assert.equal(outcome.integrityResult.reason, "hash_match");
  assert.equal(outcome.installedVersion, "0.1.0");
  assert.equal(shaCalls, 1);
});

test("decision engine: verified hash but binary version differs => update (version_mismatch)", async () => {
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
  let versionCalls = 0;
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
    },
    readInstalledBinaryVersionFn: async ({ binaryPath: seen }) => {
      versionCalls += 1;
      assert.equal(seen, binaryPath);
      return "0.0.9";
    }
  });

  assert.equal(outcome.outcome, "update");
  assert.equal(outcome.reason, "version_mismatch");
  assert.equal(outcome.installedVersion, "0.0.9");
  assert.equal(outcome.binaryVersion, "0.0.9");
  assert.equal(outcome.integrityResult.status, "verified_ok");
  assert.equal(shaCalls, 1);
  assert.equal(versionCalls, 1);
});

test("decision engine: integrity check throws => reinstall_unknown (integrity_unverifiable)", async () => {
  const platformKey = "linux-x64-gnu";
  const distDir = path.posix.join("/dist", platformKey);
  const binaryPath = path.posix.join(distDir, "docdexd");
  const metadataPath = path.posix.join(distDir, "docdexd-install.json");
  const expectedArchiveName = `docdexd-${platformKey}.tar.gz`;
  const expectedArchiveSha256 = "c".repeat(64);

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
    expectedArchiveName,
    expectedArchiveSha256,
    expectedArchiveSource: "manifest:docdex-release-manifest.json",
    sha256FileFn: async (filePath) => {
      shaCalls += 1;
      assert.equal(filePath, binaryPath);
      throw new Error("EACCES: permission denied");
    }
  });

  assert.equal(outcome.outcome, "reinstall_unknown");
  assert.equal(outcome.action, "repair");
  assert.equal(outcome.reason, "integrity_unverifiable");
  assert.equal(outcome.plan, "repair");
  assert.equal(outcome.installedVersion, "0.1.0");
  assert.equal(outcome.integrityResult.status, "unverifiable");
  assert.equal(outcome.integrityResult.reason, "unreadable");
  assert.equal(shaCalls, 1);
});
