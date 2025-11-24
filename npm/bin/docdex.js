#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawn } = require("node:child_process");

const { detectPlatformKey } = require("../lib/platform");

function run() {
  const platformKey = detectPlatformKey();
  const binaryPath = path.join(__dirname, "..", "dist", platformKey, "docdexd");

  if (!fs.existsSync(binaryPath)) {
    console.error(
      `[docdex] Missing binary for ${platformKey}. Try reinstalling or set DOCDEX_DOWNLOAD_REPO to a repo with release assets.`
    );
    process.exit(1);
  }

  const child = spawn(binaryPath, process.argv.slice(2), { stdio: "inherit" });
  child.on("exit", (code) => process.exit(code ?? 1));
  child.on("error", (err) => {
    console.error(`[docdex] failed to launch binary: ${err.message}`);
    process.exit(1);
  });
}

run();
