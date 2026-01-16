"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { createRequire } = require("node:module");

async function runScriptWithMocks(scriptPath, { mocks, argv, env, platform, arch, stdoutIsTTY, stderrIsTTY } = {}) {
  const realRequire = createRequire(scriptPath);
  const code = fs.readFileSync(scriptPath, "utf8").replace(/^#!.*\n/, "");

  const stdout = [];
  const stderr = [];
  let exitCode = null;

  const sandbox = {
    __filename: scriptPath,
    __dirname: path.dirname(scriptPath),
    module: { exports: {} },
    exports: {},
    console: {
      log: (msg) => stdout.push(String(msg)),
      error: (msg) => stderr.push(String(msg))
    },
    process: {
      argv: argv || ["node", scriptPath],
      platform: platform || "darwin",
      arch: arch || "arm64",
      env: env || {},
      stdout: { isTTY: Boolean(stdoutIsTTY) },
      stderr: { isTTY: Boolean(stderrIsTTY) },
      exit: (code) => {
        exitCode = code;
      }
    },
    setTimeout,
    clearTimeout,
    setImmediate,
    clearImmediate,
    queueMicrotask,
    require: (request) => {
      if (mocks && Object.prototype.hasOwnProperty.call(mocks, request)) return mocks[request];
      return realRequire(request);
    }
  };

  vm.runInNewContext(code, sandbox, { filename: scriptPath });
  await new Promise((resolve) => setImmediate(resolve));

  return { exitCode, stdout: stdout.join("\n"), stderr: stderr.join("\n") };
}

test("docdex CLI wrapper: unsupported platform exits non-zero and does not attempt to run binaries", async () => {
  let spawnCalls = 0;
  let existsCalls = 0;

  class UnsupportedPlatformError extends Error {
    constructor(details) {
      super(`Unsupported platform: ${details.platform}/${details.arch}`);
      this.name = "UnsupportedPlatformError";
      this.code = "DOCDEX_UNSUPPORTED_PLATFORM";
      this.exitCode = 3;
      this.details = details;
    }
  }

  const platformModule = {
    UnsupportedPlatformError,
    detectPlatformKey: () => {
      throw new UnsupportedPlatformError({
        platform: "freebsd",
        arch: "x64",
        libc: null,
        supportedPlatformKeys: ["darwin-arm64", "linux-x64-gnu"],
        supportedTargetTriples: ["aarch64-apple-darwin", "x86_64-unknown-linux-gnu"]
      });
    }
  };

  const scriptPath = path.join(__dirname, "..", "bin", "docdex.js");
  const result = await runScriptWithMocks(scriptPath, {
    mocks: {
      "../lib/platform": platformModule,
      "node:child_process": {
        spawn: () => {
          spawnCalls += 1;
          throw new Error("unexpected spawn");
        }
      },
      "node:fs": {
        existsSync: () => {
          existsCalls += 1;
          throw new Error("unexpected fs.existsSync");
        }
      },
      "node:path": require("node:path")
    }
  });

  assert.equal(result.exitCode, 3);
  assert.ok(result.stderr.includes("[docdex] unsupported platform (freebsd/x64)"));
  assert.ok(result.stderr.includes("[docdex] error code: DOCDEX_UNSUPPORTED_PLATFORM"));
  assert.ok(result.stderr.includes("[docdex] No download/run was attempted for this platform."));
  assert.equal(spawnCalls, 0);
  assert.equal(existsCalls, 0);
});

test("docdex CLI wrapper: supported platform with missing local binary exits non-zero without 'unsupported platform'", async () => {
  let spawnCalls = 0;

  const platformModule = {
    UnsupportedPlatformError: class UnsupportedPlatformError extends Error {},
    detectPlatformKey: () => "darwin-arm64",
    targetTripleForPlatformKey: () => "aarch64-apple-darwin",
    assetPatternForPlatformKey: () => "docdexd-<platformKey>.tar.gz (e.g. docdexd-darwin-arm64.tar.gz)"
  };

  const scriptPath = path.join(__dirname, "..", "bin", "docdex.js");
  const result = await runScriptWithMocks(scriptPath, {
    mocks: {
      "../lib/platform": platformModule,
      "node:child_process": {
        spawn: () => {
          spawnCalls += 1;
          throw new Error("unexpected spawn");
        }
      },
      "node:fs": { existsSync: () => false },
      "node:path": require("node:path")
    },
    argv: ["node", scriptPath, "--version"]
  });

  assert.equal(result.exitCode, 1);
  assert.ok(result.stderr.includes("[docdex] Missing binary for darwin-arm64."));
  assert.ok(!result.stderr.includes("unsupported platform"));
  assert.equal(spawnCalls, 0);
});

test("docdex CLI wrapper: `doctor` prints platform diagnostics without checking local binaries", async () => {
  let spawnCalls = 0;
  let existsCalls = 0;

  const platformModule = {
    UnsupportedPlatformError: class UnsupportedPlatformError extends Error {},
    detectLibcFromRuntime: () => null,
    detectPlatformKey: () => "darwin-arm64",
    targetTripleForPlatformKey: () => "aarch64-apple-darwin",
    artifactName: () => "docdexd-darwin-arm64.tar.gz",
    assetPatternForPlatformKey: () => "docdexd-<platformKey>.tar.gz (e.g. docdexd-darwin-arm64.tar.gz)"
  };

  const scriptPath = path.join(__dirname, "..", "bin", "docdex.js");
  const result = await runScriptWithMocks(scriptPath, {
    mocks: {
      "../lib/platform": platformModule,
      "node:child_process": {
        spawn: () => {
          spawnCalls += 1;
          throw new Error("unexpected spawn");
        }
      },
      "node:fs": {
        existsSync: () => {
          existsCalls += 1;
          throw new Error("unexpected fs.existsSync");
        }
      },
      "node:path": require("node:path")
    },
    argv: ["node", scriptPath, "doctor"]
  });

  assert.equal(result.exitCode, 0);
  assert.ok(result.stdout.includes("[docdex] doctor"));
  assert.ok(result.stdout.includes("[docdex] Supported: yes"));
  assert.ok(result.stdout.includes("[docdex] Platform key: darwin-arm64"));
  assert.ok(result.stdout.includes("[docdex] Expected target triple: aarch64-apple-darwin"));
  assert.ok(result.stdout.includes("[docdex] Expected release asset: docdexd-darwin-arm64.tar.gz"));
  assert.ok(result.stdout.includes("[docdex] Asset naming pattern: docdexd-<platformKey>.tar.gz"));
  assert.ok(result.stdout.includes("[docdex] Install source:"));
  assert.equal(spawnCalls, 0);
  assert.equal(existsCalls, 0);
});

test("docdex CLI wrapper: `doctor` exits non-zero and reports unsupported platform", async () => {
  let spawnCalls = 0;
  let existsCalls = 0;

  class UnsupportedPlatformError extends Error {
    constructor(details) {
      super(`Unsupported platform: ${details.platform}/${details.arch}`);
      this.name = "UnsupportedPlatformError";
      this.code = "DOCDEX_UNSUPPORTED_PLATFORM";
      this.exitCode = 3;
      this.details = details;
    }
  }

  const platformModule = {
    UnsupportedPlatformError,
    detectLibcFromRuntime: () => null,
    artifactName: (platformKey) => `docdexd-${platformKey}.tar.gz`,
    assetPatternForPlatformKey: (platformKey) =>
      `docdexd-<platformKey>.tar.gz (e.g. docdexd-${platformKey}.tar.gz)`,
    detectPlatformKey: () => {
      throw new UnsupportedPlatformError({
        platform: "linux",
        arch: "arm64",
        libc: "musl",
        candidatePlatformKey: "linux-arm64-musl",
        candidateTargetTriple: "aarch64-unknown-linux-musl",
        supportedPlatformKeys: ["darwin-arm64", "linux-x64-gnu"],
        supportedTargetTriples: ["aarch64-apple-darwin", "x86_64-unknown-linux-gnu"]
      });
    }
  };

  const scriptPath = path.join(__dirname, "..", "bin", "docdex.js");
  const result = await runScriptWithMocks(scriptPath, {
    mocks: {
      "../lib/platform": platformModule,
      "node:child_process": {
        spawn: () => {
          spawnCalls += 1;
          throw new Error("unexpected spawn");
        }
      },
      "node:fs": {
        existsSync: () => {
          existsCalls += 1;
          throw new Error("unexpected fs.existsSync");
        }
      },
      "node:path": require("node:path")
    },
    argv: ["node", scriptPath, "doctor"]
  });

  assert.equal(result.exitCode, 3);
  assert.ok(result.stderr.includes("[docdex] doctor"));
  assert.ok(result.stderr.includes("[docdex] Supported: no"));
  assert.ok(result.stderr.includes("[docdex] Detected platform: linux/arm64/musl"));
  assert.ok(result.stderr.includes("[docdex] error code: DOCDEX_UNSUPPORTED_PLATFORM"));
  assert.ok(result.stderr.includes("[docdex] No download/install is attempted for this platform."));
  assert.ok(result.stderr.includes("[docdex] Platform key: linux-arm64-musl"));
  assert.ok(result.stderr.includes("[docdex] Target triple: aarch64-unknown-linux-musl"));
  assert.ok(result.stderr.includes("[docdex] Asset naming pattern: docdexd-<platformKey>.tar.gz"));
  assert.equal(spawnCalls, 0);
  assert.equal(existsCalls, 0);
});
