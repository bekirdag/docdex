"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { createRequire } = require("node:module");

function runScriptWithMocks(scriptPath, { mocks, argv }) {
  const realRequire = createRequire(scriptPath);
  const code = fs.readFileSync(scriptPath, "utf8").replace(/^#!.*\n/, "");

  const stderr = [];
  let exitCode = null;

  const sandbox = {
    __filename: scriptPath,
    __dirname: path.dirname(scriptPath),
    module: { exports: {} },
    exports: {},
    console: {
      error: (msg) => stderr.push(String(msg))
    },
    process: {
      argv: argv || ["node", scriptPath],
      platform: "darwin",
      arch: "arm64",
      exit: (code) => {
        exitCode = code;
        const err = new Error("process.exit");
        err.__EXIT__ = true;
        throw err;
      }
    },
    require: (request) => {
      if (mocks && Object.prototype.hasOwnProperty.call(mocks, request)) return mocks[request];
      return realRequire(request);
    }
  };

  try {
    vm.runInNewContext(code, sandbox, { filename: scriptPath });
  } catch (err) {
    if (!err || err.__EXIT__ !== true) throw err;
  }

  return { exitCode, stderr: stderr.join("\n") };
}

test("docdex CLI wrapper: unsupported platform exits non-zero and does not attempt to run binaries", () => {
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
  const result = runScriptWithMocks(scriptPath, {
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

test("docdex CLI wrapper: supported platform with missing local binary exits non-zero without 'unsupported platform'", () => {
  let spawnCalls = 0;

  const platformModule = {
    UnsupportedPlatformError: class UnsupportedPlatformError extends Error {},
    detectPlatformKey: () => "darwin-arm64",
    targetTripleForPlatformKey: () => "aarch64-apple-darwin",
    assetPatternForPlatformKey: () => "docdexd-<platformKey>.tar.gz (e.g. docdexd-darwin-arm64.tar.gz)"
  };

  const scriptPath = path.join(__dirname, "..", "bin", "docdex.js");
  const result = runScriptWithMocks(scriptPath, {
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
