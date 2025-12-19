"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { runInstaller } = require("../lib/install");
const { targetTripleForPlatformKey } = require("../lib/platform");
const pkg = require("../package.json");

<<<<<<< HEAD
function createCapturingLogger() {
  const logs = [];
  const warns = [];
  return {
    logger: {
      log: (...args) => logs.push(args.join(" ")),
      warn: (...args) => warns.push(args.join(" ")),
      error: (...args) => warns.push(args.join(" "))
    },
    logs,
    warns
  };
}

async function ensureDir(dirPath) {
  await fs.promises.mkdir(dirPath, { recursive: true });
}

test("installer resolves versions deterministically from env and package metadata", async () => {
  const base = "https://example.test/releases/download";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const archive = "docdexd-linux-x64-gnu.tar.gz";
  const originalEnv = process.env.DOCDEX_VERSION;

  async function runCase({ label, envVersion, expectedVersion }) {
    if (envVersion == null) {
      delete process.env.DOCDEX_VERSION;
    } else {
      process.env.DOCDEX_VERSION = envVersion;
    }

    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), `docdex-installer-version-${label}-`));
    const tmpDir = path.join(tmpRoot, "tmp");
    const distBaseDir = path.join(tmpRoot, "dist");
    await ensureDir(tmpDir);

    const { logger, logs } = createCapturingLogger();
    let resolvedVersion = null;
    let downloadUrl = null;
    let downloadDest = null;

    try {
      await runInstaller({
        logger,
        platform: "linux",
        arch: "x64",
        tmpDir,
        distBaseDir,
        detectPlatformKeyFn: () => platformKey,
        targetTripleForPlatformKeyFn: () => targetTriple,
        parseRepoSlugFn: () => "owner/repo",
        getDownloadBaseFn: () => base,
        resolveInstallerDownloadPlanFn: async ({ version, platformKey: key, targetTriple: triple }) => {
          resolvedVersion = version;
          assert.equal(key, platformKey);
          assert.equal(triple, targetTriple);
          return {
            archive,
            expectedSha256: null,
            source: "fallback",
            manifestAttempt: { errors: [], resolved: null, manifestName: null }
          };
        },
        downloadFn: async (url, dest) => {
          downloadUrl = url;
          downloadDest = dest;
          await ensureDir(path.dirname(dest));
          await fs.promises.writeFile(dest, "fake-archive-bytes");
        },
        verifyDownloadedFileIntegrityFn: async ({ filePath }) => {
          assert.equal(filePath, downloadDest);
          return null;
        },
        extractTarballFn: async (_archivePath, targetDir) => {
          await ensureDir(targetDir);
          await fs.promises.writeFile(path.join(targetDir, "docdexd"), "docdexd\n");
        }
      });
    } finally {
      await fs.promises.rm(tmpRoot, { recursive: true, force: true });
    }

    assert.equal(resolvedVersion, expectedVersion);
    assert.equal(downloadUrl, `${base}/v${expectedVersion}/${archive}`);
    const fetchLine = logs.find((line) => line.includes("[docdex] Fetching "));
    assert.ok(fetchLine);
    assert.ok(fetchLine.includes(archive));
    assert.ok(fetchLine.includes(targetTriple));
    assert.ok(fetchLine.includes("linux/x64"));
    assert.ok(fetchLine.includes(`v${expectedVersion}`));
  }

  try {
    await runCase({ label: "env", envVersion: "v9.9.9", expectedVersion: "9.9.9" });
    await runCase({ label: "package", envVersion: null, expectedVersion: pkg.version });
  } finally {
    if (originalEnv == null) delete process.env.DOCDEX_VERSION;
    else process.env.DOCDEX_VERSION = originalEnv;
  }
=======
function createNoopLogger() {
  return {
    log: () => {},
    warn: () => {},
    error: () => {}
  };
}

async function ensureParentDir(filePath) {
  await fs.promises.mkdir(path.dirname(filePath), { recursive: true });
}

async function runInstallerForVersionTest(t, envVersion) {
  const prevVersion = process.env.DOCDEX_VERSION;
  if (envVersion == null) {
    delete process.env.DOCDEX_VERSION;
  } else {
    process.env.DOCDEX_VERSION = envVersion;
  }
  t.after(() => {
    if (prevVersion == null) {
      delete process.env.DOCDEX_VERSION;
    } else {
      process.env.DOCDEX_VERSION = prevVersion;
    }
  });

  const base = "https://example.test/releases/download";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-version-"));
  const tmpDir = path.join(tmpRoot, "tmp");
  const distBaseDir = path.join(tmpRoot, "dist");
  await fs.promises.mkdir(tmpDir, { recursive: true });
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  let capturedVersion = null;
  let downloadUrl = null;
  let downloadDest = null;

  const result = await runInstaller({
    logger: createNoopLogger(),
    platform: "linux",
    arch: "x64",
    distBaseDir,
    tmpDir,
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
    parseRepoSlugFn: () => "owner/repo",
    resolveInstallerDownloadPlanFn: async ({ platformKey: key, targetTriple: triple, version }) => {
      capturedVersion = version;
      assert.equal(key, platformKey);
      assert.equal(triple, targetTriple);
      return {
        archive: "docdexd-linux-x64-gnu.tar.gz",
        expectedSha256: null,
        source: "fallback",
        manifestAttempt: { errors: [], resolved: null, manifestName: null }
      };
    },
    getDownloadBaseFn: () => base,
    downloadFn: async (url, dest) => {
      downloadUrl = url;
      downloadDest = dest;
      await ensureParentDir(dest);
      await fs.promises.writeFile(dest, "fake-archive");
    },
    verifyDownloadedFileIntegrityFn: async () => null,
    extractTarballFn: async (_archivePath, targetDir) => {
      await fs.promises.mkdir(targetDir, { recursive: true });
      const binaryPath = path.join(targetDir, "docdexd");
      await fs.promises.writeFile(binaryPath, "docdexd");
    }
  });

  assert.ok(downloadDest, "expected download destination to be set");
  return { capturedVersion, downloadUrl, result };
}

test("installer uses npm package version when DOCDEX_VERSION is unset", async (t) => {
  const { capturedVersion, downloadUrl, result } = await runInstallerForVersionTest(t, null);
  assert.equal(capturedVersion, pkg.version);
  assert.equal(
    downloadUrl,
    `https://example.test/releases/download/v${pkg.version}/docdexd-linux-x64-gnu.tar.gz`
  );
  assert.ok(fs.existsSync(result.binaryPath));
});

test("installer strips leading v from DOCDEX_VERSION for tag resolution", async (t) => {
  const { capturedVersion, downloadUrl, result } = await runInstallerForVersionTest(t, "v9.9.9");
  assert.equal(capturedVersion, "9.9.9");
  assert.equal(downloadUrl, "https://example.test/releases/download/v9.9.9/docdexd-linux-x64-gnu.tar.gz");
  assert.ok(fs.existsSync(result.binaryPath));
>>>>>>> mcoda/task/ops-01-us-01-t22
});
