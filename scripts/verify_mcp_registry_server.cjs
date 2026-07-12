#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

function canonical(server) {
  return {
    name: server.name,
    description: server.description,
    repository: server.repository,
    version: server.version,
    packages: (server.packages || []).map((pkg) => ({
      registryType: pkg.registryType,
      identifier: pkg.identifier,
      version: pkg.version,
      transport: {
        type: pkg.transport?.type,
        url: pkg.transport?.url,
      },
    })),
  };
}

function main() {
  if (process.argv.length !== 4) {
    throw new Error("usage: verify_mcp_registry_server.cjs REMOTE_JSON LOCAL_SERVER_JSON");
  }
  const remotePath = path.resolve(process.argv[2]);
  const localPath = path.resolve(process.argv[3]);
  const remoteDocument = JSON.parse(fs.readFileSync(remotePath, "utf8"));
  const local = JSON.parse(fs.readFileSync(localPath, "utf8"));
  if (!remoteDocument || typeof remoteDocument !== "object" || !remoteDocument.server) {
    throw new Error("MCP Registry response is missing the server object");
  }
  assert.deepStrictEqual(canonical(remoteDocument.server), canonical(local));
  process.stdout.write(`verified ${local.name}@${local.version} canonical registry metadata\n`);
}

main();
