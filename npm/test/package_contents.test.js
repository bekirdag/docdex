"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

function resolveNpmCommand() {
  const npmExec = process.env.npm_execpath;
  if (npmExec) return { cmd: process.execPath, args: [npmExec] };
  const npmCmd = process.platform === "win32" ? "npm.cmd" : "npm";
  return { cmd: npmCmd, args: [] };
}

function readPackList() {
  const cwd = path.join(__dirname, "..");
  const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-npm-cache-"));
  let stdout = "";
  const { cmd, args } = resolveNpmCommand();
  try {
    stdout = execFileSync(cmd, args.concat(["pack", "--dry-run", "--json", "--ignore-scripts"]), {
      cwd,
      encoding: "utf8",
      env: {
        ...process.env,
        npm_config_cache: cacheDir,
        npm_config_loglevel: "silent"
      }
    });
  } finally {
    fs.rmSync(cacheDir, { recursive: true, force: true });
  }
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
