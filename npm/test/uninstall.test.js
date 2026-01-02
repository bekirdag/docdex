const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const { removeMcpServerJson, removeCodexConfig, removeMcpServerYaml } = require("../lib/uninstall");

test("removeMcpServerJson drops docdex entry", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-uninstall-json-"));
  const file = path.join(dir, "config.json");
  fs.writeFileSync(
    file,
    JSON.stringify(
      {
        mcpServers: {
          docdex: { url: "http://localhost:3000/sse" },
          other: { url: "http://localhost:7777/sse" }
        }
      },
      null,
      2
    )
  );
  const changed = removeMcpServerJson(file);
  assert.equal(changed, true);
  const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.ok(!parsed.mcpServers?.docdex);
  assert.equal(parsed.mcpServers.other.url, "http://localhost:7777/sse");
});

test("removeMcpServerJson drops docdex from mcp_servers", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-uninstall-json-"));
  const file = path.join(dir, "config.json");
  fs.writeFileSync(
    file,
    JSON.stringify(
      {
        mcp_servers: {
          docdex: { url: "http://localhost:3000/sse" },
          other: { url: "http://localhost:7777/sse" }
        }
      },
      null,
      2
    )
  );
  const changed = removeMcpServerJson(file);
  assert.equal(changed, true);
  const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.ok(!parsed.mcp_servers?.docdex);
  assert.equal(parsed.mcp_servers.other.url, "http://localhost:7777/sse");
});

test("removeCodexConfig removes docdex from mcp_servers table", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-uninstall-codex-"));
  const file = path.join(dir, "config.toml");
  fs.writeFileSync(
    file,
    [
      'model = "gpt-5.1-codex-max"',
      "",
      "[mcp_servers]",
      'docdex = { url = "http://localhost:3000/sse" }',
      'other = { url = "http://localhost:7777/sse" }',
      ""
    ].join("\n")
  );
  const changed = removeCodexConfig(file);
  assert.equal(changed, true);
  const contents = fs.readFileSync(file, "utf8");
  assert.ok(!contents.includes("docdex ="));
  assert.ok(contents.includes("other ="));
});

test("removeCodexConfig removes docdex nested section", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-uninstall-codex-nested-"));
  const file = path.join(dir, "config.toml");
  fs.writeFileSync(
    file,
    [
      "[mcp_servers.docdex]",
      'url = "http://localhost:3000/sse"',
      "",
      "[mcp_servers.other]",
      'url = "http://localhost:7777/sse"',
      ""
    ].join("\n")
  );
  const changed = removeCodexConfig(file);
  assert.equal(changed, true);
  const contents = fs.readFileSync(file, "utf8");
  assert.ok(!contents.includes("mcp_servers.docdex"));
  assert.ok(contents.includes("mcp_servers.other"));
});

test("removeCodexConfig removes legacy docdex block", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-uninstall-codex-legacy-"));
  const file = path.join(dir, "config.toml");
  fs.writeFileSync(
    file,
    [
      "[[mcp_servers]]",
      'name = "docdex"',
      'url = "http://localhost:3000/sse"',
      "",
      "[[mcp_servers]]",
      'name = "other"',
      'url = "http://localhost:7777/sse"',
      ""
    ].join("\n")
  );
  const changed = removeCodexConfig(file);
  assert.equal(changed, true);
  const contents = fs.readFileSync(file, "utf8");
  assert.ok(!contents.includes('name = "docdex"'));
  assert.ok(contents.includes('name = "other"'));
});

test("removeMcpServerYaml removes docdex entries", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-uninstall-yaml-"));
  const file = path.join(dir, "config.yml");
  fs.writeFileSync(
    file,
    [
      "mcp_servers:",
      "  docdex:",
      "    url: http://localhost:3000/sse",
      "  other:",
      "    url: http://localhost:7777/sse",
      ""
    ].join("\n")
  );
  const changed = removeMcpServerYaml(file);
  assert.equal(changed, true);
  const contents = fs.readFileSync(file, "utf8");
  assert.ok(!contents.includes("docdex:"));
  assert.ok(contents.includes("other:"));
});
