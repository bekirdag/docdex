"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const cwd = path.resolve(__dirname, "..");

const resolveNpmCommand = () => {
  const npmExec = process.env.npm_execpath;
  if (npmExec) return { cmd: process.execPath, args: [npmExec] };
  const npmCmd = process.platform === "win32" ? "npm.cmd" : "npm";
  return { cmd: npmCmd, args: [] };
};

const bannedMatchers = [
  { pattern: /(^|\/)docdexd(\.exe)?$/i, reason: "docdexd binary" },
  { pattern: /(^|\/)docdexd-.*\.(tar\.gz|zip)$/i, reason: "docdexd release archive" },
  { pattern: /\.node$/i, reason: "native Node module" },
  { pattern: /\.so$/i, reason: "shared object" },
  { pattern: /\.dylib$/i, reason: "dynamic library" },
  { pattern: /\.dll$/i, reason: "Windows DLL" },
  { pattern: /\.exe$/i, reason: "Windows executable" },
  { pattern: /\.a$/i, reason: "static archive" },
  { pattern: /\.lib$/i, reason: "static library" },
];

const normalizePath = (value) => value.replace(/\\/g, "/");

const getPackList = () => {
  const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-npm-cache-"));
  let stdout = "";
  const { cmd, args } = resolveNpmCommand();
  try {
    stdout = execFileSync(cmd, args.concat(["pack", "--dry-run", "--json", "--ignore-scripts"]), {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        npm_config_cache: cacheDir,
        npm_config_loglevel: "silent"
      },
    });
  } finally {
    fs.rmSync(cacheDir, { recursive: true, force: true });
  }

  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch (err) {
    throw new Error(
      `npm pack --dry-run --json did not return JSON: ${err.message}\n${stdout}`
    );
  }

  const entries = Array.isArray(parsed) ? parsed : [parsed];
  return entries
    .flatMap((entry) => (entry.files || []).map((file) => (typeof file === "string" ? file : file.path)))
    .filter(Boolean)
    .map(normalizePath);
};

test("npm tarball excludes native docdexd binaries", () => {
  const files = getPackList();
  const offenders = [];

  for (const file of files) {
    for (const { pattern, reason } of bannedMatchers) {
      if (pattern.test(file)) {
        offenders.push(`${file} (${reason})`);
        break;
      }
    }
  }

  assert.equal(
    offenders.length,
    0,
    `Packaging guardrails violated. Remove native artifacts from npm package:\n${offenders.join("\n")}`
  );
});
