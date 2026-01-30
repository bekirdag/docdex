#!/usr/bin/env node
"use strict";

const { runBridge } = require("./mcp_stdio_bridge");

async function main() {
  try {
    await runBridge({ stdin: process.stdin, stdout: process.stdout, stderr: process.stderr });
  } catch (err) {
    process.stderr.write(`[docdex-mcp-stdio] fatal: ${err}\n`);
    process.exit(1);
  }
}

main();
