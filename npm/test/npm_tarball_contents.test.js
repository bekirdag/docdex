"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

function getNpmCommand() {
  const npmExec = process.env.npm_execpath;
  if (npmExec) return { cmd: process.execPath, args: [npmExec] };
  return { cmd: process.platform === "win32" ? "npm.cmd" : "npm", args: [] };
}

function withTempNpmCache(run) {
  const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-npm-cache-"));
  try {
    return run(cacheDir);
  } finally {
    fs.rmSync(cacheDir, { recursive: true, force: true });
  }
}

test("npm tarball excludes native docdexd binaries", () => {
  const pkgRoot = path.resolve(__dirname, "..");
  let stdout = "";
  const { cmd, args } = getNpmCommand();

  try {
    stdout = withTempNpmCache((cacheDir) =>
      execFileSync(cmd, args.concat(["pack", "--dry-run", "--json", "--ignore-scripts"]), {
        cwd: pkgRoot,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
        env: {
          ...process.env,
          npm_config_cache: cacheDir,
          npm_config_loglevel: "silent"
        }
      })
    );
  } catch (err) {
    const message = err?.stderr ? String(err.stderr) : err?.message || String(err);
    throw new Error(`npm pack failed: ${message}`);
  }

  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch (err) {
    throw new Error(`npm pack output was not valid JSON: ${err?.message || String(err)}`);
  }

  const entries = Array.isArray(parsed) ? parsed : [parsed];
  const files = entries.flatMap((entry) => entry.files || []);

  assert.ok(files.length > 0, "expected npm pack to report file list");

  const paths = files
    .map((file) => (typeof file === "string" ? file : file?.path))
    .filter(Boolean)
    .map((filePath) => String(filePath).replace(/\\/g, "/"));

  const forbidden = paths.filter((filePath) => {
    const isDist = filePath === "dist" || filePath.startsWith("dist/");
    const isBinary = /(^|\/)docdexd(\.exe)?$/.test(filePath);
    return isDist || isBinary;
  });

  assert.equal(
    forbidden.length,
    0,
    `unexpected native binaries in npm tarball: ${forbidden.join(", ")}`
  );
});
