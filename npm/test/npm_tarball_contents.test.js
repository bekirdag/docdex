"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const path = require("node:path");

function getNpmCommand() {
  return process.platform === "win32" ? "npm.cmd" : "npm";
}

test("npm tarball excludes native docdexd binaries", () => {
  const pkgRoot = path.resolve(__dirname, "..");
  let stdout = "";

  try {
    stdout = execFileSync(getNpmCommand(), ["pack", "--dry-run", "--json", "--ignore-scripts"], {
      cwd: pkgRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"]
    });
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
