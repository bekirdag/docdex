"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { parseDocdexdVersion, probeDocdexdVersion } = require("../lib/daemon_version");

test("parseDocdexdVersion extracts semver from version output", () => {
  assert.equal(parseDocdexdVersion("docdexd 1.2.3"), "1.2.3");
  assert.equal(parseDocdexdVersion("docdexd v1.2.3-beta.1+build.5"), "1.2.3-beta.1+build.5");
});

test("parseDocdexdVersion returns null when no semver is present", () => {
  assert.equal(parseDocdexdVersion("docdexd version unknown"), null);
});

test("probeDocdexdVersion returns not_installed when binary missing", async () => {
  const fsModule = { existsSync: () => false };
  const result = await probeDocdexdVersion({ binaryPath: "/missing/docdexd", fsModule });
  assert.equal(result.status, "not_installed");
  assert.equal(result.version, null);
});

test("probeDocdexdVersion treats EACCES as not_installed", async () => {
  const fsModule = { existsSync: () => true };
  const execFileFn = (_bin, _args, _opts, cb) => {
    const err = new Error("EACCES");
    err.code = "EACCES";
    cb(err);
  };
  const result = await probeDocdexdVersion({
    binaryPath: "/no/exec/docdexd",
    fsModule,
    execFileFn
  });
  assert.equal(result.status, "not_installed");
  assert.equal(result.version, null);
});

test("probeDocdexdVersion reads version from a fake binary", async (t) => {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-version-probe-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const isWin32 = process.platform === "win32";
  const binaryPath = path.join(tmpRoot, isWin32 ? "docdexd.cmd" : "docdexd");
  const payload = isWin32
    ? "@echo docdexd 9.8.7\r\n"
    : "#!/bin/sh\necho \"docdexd 9.8.7\"\n";

  fs.writeFileSync(binaryPath, payload, { mode: 0o755 });
  if (!isWin32) {
    await fs.promises.chmod(binaryPath, 0o755);
  }

  const result = await probeDocdexdVersion({ binaryPath, timeoutMs: 2000 });
  assert.equal(result.status, "installed");
  assert.equal(result.version, "9.8.7");
});
