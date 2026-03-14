const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const {
  removeMcpServerJson,
  removeCodexConfig,
  removeMcpServerYaml,
  removeDocdexRootIfEmpty
} = require("../lib/uninstall");

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

test("removeMcpServerJson drops docdex from array mcpServers", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-uninstall-array-"));
  const file = path.join(dir, "config.json");
  fs.writeFileSync(
    file,
    JSON.stringify(
      {
        mcpServers: [
          { name: "docdex", url: "http://localhost:3000/sse" },
          { name: "other", url: "http://localhost:7777/sse" }
        ]
      },
      null,
      2
    )
  );
  const changed = removeMcpServerJson(file);
  assert.equal(changed, true);
  const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.equal(parsed.mcpServers.length, 1);
  assert.equal(parsed.mcpServers[0].name, "other");
});

test("removeMcpServerJson drops docdex from experimental_mcp_servers", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-uninstall-zed-"));
  const file = path.join(dir, "config.json");
  fs.writeFileSync(
    file,
    JSON.stringify(
      {
        experimental_mcp_servers: {
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
  assert.ok(!parsed.experimental_mcp_servers?.docdex);
  assert.equal(parsed.experimental_mcp_servers.other.url, "http://localhost:7777/sse");
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

test("removeCodexConfig removes empty mcp_servers table", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-uninstall-codex-empty-"));
  const file = path.join(dir, "config.toml");
  fs.writeFileSync(
    file,
    [
      'model = "gpt-5.1-codex-max"',
      "",
      "[mcp_servers]",
      'docdex = { url = "http://localhost:3000/sse" }',
      ""
    ].join("\n")
  );
  const changed = removeCodexConfig(file);
  assert.equal(changed, true);
  const contents = fs.readFileSync(file, "utf8");
  assert.ok(!contents.includes("docdex ="));
  assert.ok(!contents.includes("[mcp_servers]"));
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

test("removeDocdexRootIfEmpty preserves persistent docdex state", () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-uninstall-home-"));
  const root = path.join(home, ".docdex");
  const telemetryPath = path.join(root, "state", "telemetry", "delegation.json");
  const indexPath = path.join(root, "state", "repos", "repo-1", "index", "docs.sqlite");
  const configPath = path.join(root, "config.toml");
  fs.mkdirSync(path.dirname(telemetryPath), { recursive: true });
  fs.mkdirSync(path.dirname(indexPath), { recursive: true });
  fs.writeFileSync(telemetryPath, '{"delegate_requests_total":93}\n');
  fs.writeFileSync(indexPath, "sqlite");
  fs.writeFileSync(configPath, "[server]\nhttp_bind_addr = \"127.0.0.1:28491\"\n");

  const removed = removeDocdexRootIfEmpty({
    fsModule: fs,
    osModule: { homedir: () => home },
    pathModule: path
  });

  assert.equal(removed, false);
  assert.ok(fs.existsSync(root));
  assert.equal(
    fs.readFileSync(telemetryPath, "utf8"),
    '{"delegate_requests_total":93}\n'
  );
  assert.ok(fs.existsSync(indexPath));
  assert.ok(fs.existsSync(configPath));
});

test("removeDocdexRootIfEmpty removes an empty docdex root", () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-uninstall-empty-home-"));
  const root = path.join(home, ".docdex");
  fs.mkdirSync(root, { recursive: true });

  const removed = removeDocdexRootIfEmpty({
    fsModule: fs,
    osModule: { homedir: () => home },
    pathModule: path
  });

  assert.equal(removed, true);
  assert.equal(fs.existsSync(root), false);
});
