const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const {
  upsertServerConfig,
  parseServerBind,
  upsertMcpServerJson,
  upsertCodexConfig,
  configUrlForPort
} = require("../lib/postinstall_setup");

test("upsertServerConfig adds server section when missing", () => {
  const updated = upsertServerConfig("", "127.0.0.1:3000");
  assert.ok(updated.includes("[server]"));
  assert.ok(updated.includes('http_bind_addr = "127.0.0.1:3000"'));
  assert.ok(updated.includes("enable_mcp = true"));
});

test("parseServerBind reads existing http_bind_addr", () => {
  const contents = ["[server]", "http_bind_addr = \"127.0.0.1:3210\""].join("\n");
  assert.equal(parseServerBind(contents), "127.0.0.1:3210");
});

test("upsertMcpServerJson sets docdex url", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-json-"));
  const file = path.join(dir, "config.json");
  const url = configUrlForPort(3000);
  const changed = upsertMcpServerJson(file, url);
  assert.equal(changed, true);
  const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.equal(parsed.mcpServers.docdex.url, url);
});

test("upsertCodexConfig appends docdex server", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-codex-"));
  const file = path.join(dir, "config.toml");
  const url = configUrlForPort(3210);
  const changed = upsertCodexConfig(file, url);
  assert.equal(changed, true);
  const contents = fs.readFileSync(file, "utf8");
  assert.ok(contents.includes('name = "docdex"'));
  assert.ok(contents.includes(`url = "${url}"`));
});
