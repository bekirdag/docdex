"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

function readPackList() {
  const cwd = path.join(__dirname, "..");
  const stdout = execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
    cwd,
    encoding: "utf8"
  });
  const parsed = JSON.parse(stdout.trim());
  const info = Array.isArray(parsed) ? parsed[0] : parsed;
  const files = Array.isArray(info?.files) ? info.files : [];
  return files.map((file) => (typeof file === "string" ? file : file.path));
}

test("npm tarball excludes native docdexd binaries and archives", () => {
  const files = readPackList();
  assert.ok(files.length > 0);

  const forbiddenPatterns = [
    /(^|\/)docdexd(\.exe)?$/,
    /(^|\/)docdexd-.*\.tar\.gz(\.sha256)?$/
  ];

  const forbidden = files.filter((file) => {
    if (typeof file !== "string") return false;
    return forbiddenPatterns.some((pattern) => pattern.test(file));
  });

  assert.deepEqual(forbidden, []);
});
