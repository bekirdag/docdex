"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { runInstaller } = require("../lib/install");

function noopLogger() {
  return { log: () => {}, warn: () => {}, error: () => {} };
}

test("installer falls back to local binary when integrity metadata is missing", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-local-fallback-"));
  t.after(() => fs.promises.rm(tmp, { recursive: true, force: true }));

  const repoRoot = path.join(tmp, "repo");
  const binaryName = process.platform === "win32" ? "docdexd.exe" : "docdexd";
  const binaryPath = path.join(repoRoot, "target", "release", binaryName);
  await fs.promises.mkdir(path.dirname(binaryPath), { recursive: true });
  await fs.promises.writeFile(binaryPath, "local-binary\n");

  const distBaseDir = path.join(tmp, "dist");
  const platformKey = "linux-x64-gnu";
  const targetTriple = "x86_64-unknown-linux-gnu";

  const result = await runInstaller({
    logger: noopLogger(),
    platform: "linux",
    arch: "x64",
    distBaseDir,
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
    parseRepoSlugFn: () => "local/test",
    resolveInstallerDownloadPlanFn: async () => {
      const err = new Error("missing checksums");
      err.code = "DOCDEX_CHECKSUM_UNUSABLE";
      throw err;
    },
    localRepoRoot: repoRoot
  });

  assert.equal(result.outcome, "local");
  assert.ok(fs.existsSync(result.binaryPath));
});
