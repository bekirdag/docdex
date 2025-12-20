import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const cwd = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

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
  const stdout = execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });

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
