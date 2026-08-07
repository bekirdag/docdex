const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { version: PACKAGE_VERSION } = require("../package.json");

const {
  upsertServerConfig,
  parseServerBind,
  upsertMcpServerJson,
  upsertZedConfig,
  upsertCodexConfig,
  warnCodexRestart,
  configUrlForPort,
  configStreamableUrlForPort,
  resolveDaemonPort,
  runPostInstallSetup,
  resolveDaemonPortState,
  normalizeVersion,
  resolveOllamaInstallMode,
  resolveOllamaModelPromptMode,
  parseOllamaListOutput,
  formatGiB,
  readLlmDefaultModel,
  upsertLlmDefaultModel,
  pullOllamaModel,
  hasInteractiveTty,
  shouldSkipSetup,
  launchSetupWizard,
  applyAgentInstructions,
  buildDaemonEnv,
  buildLaunchAgentPlist,
  startDaemonWithHealthCheck,
  waitForDaemonReady
} = require("../lib/postinstall_setup");

async function withTempHome(prefix, callback) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  const keys = ["HOME", "USERPROFILE", "APPDATA"];
  const previous = Object.fromEntries(keys.map((key) => [key, process.env[key]]));
  process.env.HOME = dir;
  process.env.USERPROFILE = dir;
  process.env.APPDATA = path.join(dir, "AppData", "Roaming");
  try {
    return await callback(dir);
  } finally {
    for (const key of keys) {
      if (previous[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = previous[key];
      }
    }
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test("upsertServerConfig adds server section when missing", () => {
  const updated = upsertServerConfig("", "127.0.0.1:3000");
  assert.ok(updated.includes("[server]"));
  assert.ok(updated.includes('http_bind_addr = "127.0.0.1:3000"'));
  assert.ok(updated.includes("enable_mcp = true"));
});

test("parseServerBind reads existing http_bind_addr", () => {
  const contents = ["[server]", "http_bind_addr = \"127.0.0.1:28491\""].join("\n");
  assert.equal(parseServerBind(contents), "127.0.0.1:28491");
});

test("config helpers use loopback ip to match the default daemon bind", () => {
  assert.equal(configUrlForPort(3000), "http://127.0.0.1:3000/sse");
  assert.equal(configStreamableUrlForPort(3000), "http://127.0.0.1:3000/v1/mcp");
});

test("resolveDaemonPort preserves the default and accepts valid overrides", () => {
  assert.equal(resolveDaemonPort({}), 28491);
  assert.equal(resolveDaemonPort({ DOCDEX_DAEMON_PORT: "" }), 28491);
  assert.equal(resolveDaemonPort({ DOCDEX_DAEMON_PORT: "  " }), 28491);
  assert.equal(resolveDaemonPort({ DOCDEX_DAEMON_PORT: "1" }), 1);
  assert.equal(resolveDaemonPort({ DOCDEX_DAEMON_PORT: " 45123 " }), 45123);
  assert.equal(resolveDaemonPort({ DOCDEX_DAEMON_PORT: "65535" }), 65535);
});

test("resolveDaemonPort rejects malformed or out-of-range overrides", () => {
  for (const value of ["0", "65536", "-1", "+1", "1.5", "1e3", "abc", "NaN"]) {
    assert.throws(
      () => resolveDaemonPort({ DOCDEX_DAEMON_PORT: value }),
      /DOCDEX_DAEMON_PORT must be a base-10 integer between 1 and 65535/
    );
  }
});

test("runPostInstallSetup forwards a custom daemon port to lifecycle and generated configs", async () => {
  await withTempHome("docdex-postinstall-port-", async (dir) => {
    const calls = [];
    const result = await runPostInstallSetup({
      binaryPath: process.execPath,
      logger: { warn: () => {} },
      env: {
        ...process.env,
        DOCDEX_DAEMON_PORT: "45123",
        DOCDEX_SETUP_SKIP: "1"
      },
      deps: {
        cleanupExistingDaemon: async (options) => {
          calls.push(["cleanup", options.port]);
          return true;
        },
        resolveDaemonPortState: async (options) => {
          calls.push(["resolve", options.port]);
          return { available: true, reuseExisting: false };
        },
        startDaemonWithHealthCheck: async (options) => {
          calls.push(["start", options.port]);
          return { ok: true, reason: "ready" };
        }
      }
    });

    assert.deepEqual(calls, [
      ["cleanup", 45123],
      ["resolve", 45123],
      ["start", 45123]
    ]);
    assert.equal(result.port, 45123);
    assert.equal(result.url, "http://127.0.0.1:45123/sse");
    assert.ok(
      fs.readFileSync(path.join(dir, ".docdex", "config.toml"), "utf8")
        .includes('http_bind_addr = "127.0.0.1:45123"')
    );
    const cursor = JSON.parse(fs.readFileSync(path.join(dir, ".cursor", "mcp.json"), "utf8"));
    assert.equal(cursor.mcpServers.docdex.url, "http://127.0.0.1:45123/sse");
  });
});

test("isolated daemon lifecycle bypasses global cleanup and service registration", async () => {
  await withTempHome("docdex-postinstall-isolated-", async () => {
    const calls = [];
    const forbidden = (name) => async () => {
      calls.push(name);
      throw new Error(`${name} must not run`);
    };
    const result = await runPostInstallSetup({
      binaryPath: process.execPath,
      logger: { warn: () => {} },
      env: {
        ...process.env,
        DOCDEX_DAEMON_PORT: "45124",
        DOCDEX_SETUP_SKIP: "1"
      },
      isolatedDaemonLifecycle: true,
      deps: {
        isPortAvailable: async (port, host) => {
          calls.push(["isPortAvailable", host, port]);
          return true;
        },
        cleanupExistingDaemon: forbidden("cleanupExistingDaemon"),
        resolveDaemonPortState: forbidden("resolveDaemonPortState"),
        startDaemonWithHealthCheck: forbidden("startDaemonWithHealthCheck")
      }
    });

    assert.deepEqual(calls, [["isPortAvailable", "127.0.0.1", 45124]]);
    assert.equal(result.port, 45124);
  });
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

test("upsertMcpServerJson updates array entries", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-json-array-"));
  const file = path.join(dir, "config.json");
  fs.writeFileSync(
    file,
    JSON.stringify(
      {
        mcpServers: [{ name: "docdex", url: "http://localhost:7777/v1/mcp" }]
      },
      null,
      2
    )
  );
  const url = configUrlForPort(3000);
  const changed = upsertMcpServerJson(file, url);
  assert.equal(changed, true);
  const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.equal(parsed.mcpServers[0].url, url);
});

test("upsertMcpServerJson collapses duplicate docdex entries across sections", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-json-dedupe-"));
  const file = path.join(dir, "config.json");
  fs.writeFileSync(
    file,
    JSON.stringify(
      {
        mcpServers: [
          { name: "docdex", url: "http://old1" },
          { name: "other", url: "http://other" },
          { name: "docdex", url: "http://old2" }
        ],
        mcp_servers: {
          docdex: { url: "http://stale" },
          another: { url: "http://another" }
        }
      },
      null,
      2
    )
  );
  const url = configUrlForPort(3000);
  const changed = upsertMcpServerJson(file, url);
  assert.equal(changed, true);
  const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.deepEqual(
    parsed.mcpServers.filter((entry) => entry.name === "docdex").map((entry) => entry.url),
    [url]
  );
  assert.equal(parsed.mcp_servers.docdex, undefined);
  assert.equal(parsed.mcp_servers.another.url, "http://another");
});

test("upsertMcpServerJson collapses whitespace-padded docdex entries across sections", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-json-spaced-dedupe-"));
  const file = path.join(dir, "config.json");
  fs.writeFileSync(
    file,
    JSON.stringify(
      {
        mcpServers: [
          { name: " docdex ", url: "http://old1" },
          { name: "other", url: "http://other" },
          { name: "DOCDEX", url: "http://old2" }
        ],
        mcp_servers: {
          " docdex ": { url: "http://stale" },
          another: { url: "http://another" }
        }
      },
      null,
      2
    )
  );
  const url = configUrlForPort(3000);
  const changed = upsertMcpServerJson(file, url);
  assert.equal(changed, true);
  const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.deepEqual(
    parsed.mcpServers
      .filter((entry) => typeof entry.name === "string" && entry.name.trim().toLowerCase() === "docdex")
      .map((entry) => entry.url),
    [url]
  );
  assert.equal(parsed.mcp_servers[" docdex "], undefined);
  assert.equal(parsed.mcp_servers.another.url, "http://another");
});

test("upsertMcpServerJson respects mcp_servers map", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-json-snake-"));
  const file = path.join(dir, "config.json");
  fs.writeFileSync(
    file,
    JSON.stringify(
      {
        mcp_servers: {
          docdex: { url: "http://localhost:7777/v1/mcp" }
        }
      },
      null,
      2
    )
  );
  const url = configUrlForPort(3000);
  const changed = upsertMcpServerJson(file, url);
  assert.equal(changed, true);
  const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.equal(parsed.mcp_servers.docdex.url, url);
});

test("upsertMcpServerJson merges extra fields", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-json-extra-"));
  const file = path.join(dir, "config.json");
  fs.writeFileSync(
    file,
    JSON.stringify(
      {
        mcpServers: {
          docdex: { type: "http", url: "http://localhost:7777/v1/mcp" }
        }
      },
      null,
      2
    )
  );
  const url = configStreamableUrlForPort(3000);
  const changed = upsertMcpServerJson(file, url, { extra: { type: "http" } });
  assert.equal(changed, true);
  const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.equal(parsed.mcpServers.docdex.url, url);
  assert.equal(parsed.mcpServers.docdex.type, "http");
});

test("upsertZedConfig sets experimental_mcp_servers", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-zed-"));
  const file = path.join(dir, "settings.json");
  const url = configUrlForPort(3000);
  const changed = upsertZedConfig(file, url);
  assert.equal(changed, true);
  const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.equal(parsed.experimental_mcp_servers.docdex.url, url);
});

test("upsertZedConfig normalizes whitespace-padded docdex keys", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-zed-spaced-"));
  const file = path.join(dir, "settings.json");
  fs.writeFileSync(
    file,
    JSON.stringify(
      {
        experimental_mcp_servers: {
          " docdex ": { url: "http://old" },
          other: { url: "http://other" }
        }
      },
      null,
      2
    )
  );
  const url = configUrlForPort(3000);
  const changed = upsertZedConfig(file, url);
  assert.equal(changed, true);
  const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.equal(parsed.experimental_mcp_servers[" docdex "], undefined);
  assert.equal(parsed.experimental_mcp_servers.docdex.url, url);
  assert.equal(parsed.experimental_mcp_servers.other.url, "http://other");
});

test("upsertCodexConfig appends docdex server", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-codex-"));
  const file = path.join(dir, "config.toml");
  const url = configStreamableUrlForPort(28491);
  const changed = upsertCodexConfig(file, url);
  assert.equal(changed, true);
  const contents = fs.readFileSync(file, "utf8");
  assert.ok(contents.includes("[mcp_servers]"));
  assert.ok(
    contents.includes(
      `docdex = { url = "${url}", tool_timeout_sec = 300, startup_timeout_sec = 300 }`
    )
  );
});

test("upsertCodexConfig migrates legacy mcp_servers array", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-codex-legacy-"));
  const file = path.join(dir, "config.toml");
  fs.writeFileSync(
    file,
    [
      'model = "gpt-5.1-codex-max"',
      "",
      "[[mcp_servers]]",
      'name = "docdex"',
      'url = "http://localhost:3000/sse"',
      "",
    ].join("\n")
  );
  const url = configStreamableUrlForPort(3000);
  const changed = upsertCodexConfig(file, url);
  assert.equal(changed, true);
  const contents = fs.readFileSync(file, "utf8");
  assert.ok(!contents.includes("[[mcp_servers]]"));
  assert.ok(contents.includes("[mcp_servers.docdex]"));
  assert.ok(contents.includes(`url = "${url}"`));
  assert.ok(contents.includes("tool_timeout_sec = 300"));
  assert.ok(contents.includes("startup_timeout_sec = 300"));
});

test("upsertCodexConfig fills timeout fields in nested docdex section", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-codex-nested-"));
  const file = path.join(dir, "config.toml");
  fs.writeFileSync(
    file,
    [
      "[mcp_servers.docdex]",
      'url = "http://localhost:3000/v1/mcp"',
      ""
    ].join("\n")
  );
  const url = configStreamableUrlForPort(3000);
  const changed = upsertCodexConfig(file, url);
  assert.equal(changed, true);
  const contents = fs.readFileSync(file, "utf8");
  assert.ok(contents.includes("[mcp_servers.docdex]"));
  assert.ok(contents.includes(`url = "${url}"`));
  assert.ok(contents.includes("tool_timeout_sec = 300"));
  assert.ok(contents.includes("startup_timeout_sec = 300"));
});

test("upsertCodexConfig removes stale inline docdex entry when nested tables exist", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-codex-dedupe-"));
  const file = path.join(dir, "config.toml");
  fs.writeFileSync(
    file,
    [
      "[mcp_servers]",
      'docdex = { url = "http://old/v1/mcp" }',
      "",
      "[mcp_servers.other]",
      'url = "http://other/v1/mcp"',
      ""
    ].join("\n")
  );
  const url = configStreamableUrlForPort(3000);
  const changed = upsertCodexConfig(file, url);
  assert.equal(changed, true);
  const contents = fs.readFileSync(file, "utf8");
  assert.ok(!contents.includes('docdex = { url = "http://old/v1/mcp" }'));
  assert.equal((contents.match(/\[mcp_servers\.docdex\]/g) || []).length, 1);
  assert.ok(contents.includes("[mcp_servers.other]"));
  assert.ok(contents.includes(`url = "${url}"`));
  assert.ok(contents.includes("tool_timeout_sec = 300"));
  assert.ok(contents.includes("startup_timeout_sec = 300"));
});

test("upsertCodexConfig normalizes whitespace-padded nested docdex sections", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-codex-spaced-dedupe-"));
  const file = path.join(dir, "config.toml");
  fs.writeFileSync(
    file,
    [
      "[mcp_servers]",
      'docdex = { url = "http://old-root/v1/mcp" }',
      "",
      "[mcp_servers.docdex ]",
      'url = "http://old-nested-1/v1/mcp"',
      "",
      "[mcp_servers. docdex]",
      "startup_timeout_sec = 120",
      "",
      "[mcp_servers.other]",
      'url = "http://other/v1/mcp"',
      ""
    ].join("\n")
  );
  const url = configStreamableUrlForPort(3000);
  const changed = upsertCodexConfig(file, url);
  assert.equal(changed, true);
  const contents = fs.readFileSync(file, "utf8");
  assert.ok(!contents.includes('docdex = { url = "http://old-root/v1/mcp" }'));
  assert.ok(!contents.includes("[mcp_servers.docdex ]"));
  assert.ok(!contents.includes("[mcp_servers. docdex]"));
  assert.equal((contents.match(/\[mcp_servers\.docdex\]/g) || []).length, 1);
  assert.ok(contents.includes("[mcp_servers.other]"));
  assert.ok(contents.includes(`url = "${url}"`));
  assert.ok(contents.includes("tool_timeout_sec = 300"));
  assert.ok(contents.includes("startup_timeout_sec = 300"));
});

test("upsertCodexConfig is a no-op when the root docdex entry already matches", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-codex-stable-"));
  const file = path.join(dir, "config.toml");
  const url = configStreamableUrlForPort(3000);
  const initial = [
    "[mcp_servers]",
    `docdex = { url = "${url}", tool_timeout_sec = 300, startup_timeout_sec = 300 }`,
    ""
  ].join("\n");
  fs.writeFileSync(file, initial);
  const changed = upsertCodexConfig(file, url);
  assert.equal(changed, false);
  assert.equal(fs.readFileSync(file, "utf8"), initial);
});

test("upsertCodexConfig removes legacy instructions entry", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-codex-instructions-"));
  const file = path.join(dir, "config.toml");
  fs.writeFileSync(
    file,
    [
      "[features]",
      'experimental_instructions_file = "~/.docdex/agents.md"',
      "",
      "[mcp_servers]",
      'docdex = { url = "http://localhost:3000/sse" }',
      ""
    ].join("\n")
  );
  const url = configStreamableUrlForPort(3000);
  const changed = upsertCodexConfig(file, url);
  assert.equal(changed, true);
  const contents = fs.readFileSync(file, "utf8");
  assert.ok(!contents.includes('experimental_instructions_file = "~/.docdex/agents.md"'));
});

test("warnCodexRestart only logs when Codex config changes", () => {
  const warnings = [];
  const logger = { warn: (message) => warnings.push(message) };
  warnCodexRestart(logger, false);
  assert.deepEqual(warnings, []);
  warnCodexRestart(logger, true);
  assert.deepEqual(warnings, [
    "[docdex] Codex MCP config updated. Restart Codex to reload the MCP endpoint."
  ]);
});

test("applyAgentInstructions appends versioned docdex block once", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-codex-agents-"));
  const prev = {
    HOME: process.env.HOME,
    USERPROFILE: process.env.USERPROFILE,
    APPDATA: process.env.APPDATA
  };
  process.env.HOME = dir;
  process.env.USERPROFILE = dir;
  process.env.APPDATA = path.join(dir, "AppData", "Roaming");
  try {
    const result = applyAgentInstructions({ logger: { warn: () => {} } });
    assert.equal(result.ok, true);
    const second = applyAgentInstructions({ logger: { warn: () => {} } });
    assert.equal(second.ok, true);
    const target = path.join(dir, ".codex", "AGENTS.md");
    assert.ok(fs.existsSync(target));
    const contents = fs.readFileSync(target, "utf8");
    const startMarker = `---- START OF DOCDEX INFO V${PACKAGE_VERSION} ----`;
    assert.ok(contents.includes(startMarker));
    assert.ok(contents.includes("---- END OF DOCDEX INFO -----"));
    assert.ok(contents.includes("# Docdex Agent Usage Instructions"));
    assert.equal(contents.split(startMarker).length - 1, 1);
  } finally {
    process.env.HOME = prev.HOME;
    process.env.USERPROFILE = prev.USERPROFILE;
    process.env.APPDATA = prev.APPDATA;
  }
});

test("applyAgentInstructions replaces older docdex block", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-codex-agents-old-"));
  const prev = {
    HOME: process.env.HOME,
    USERPROFILE: process.env.USERPROFILE,
    APPDATA: process.env.APPDATA
  };
  process.env.HOME = dir;
  process.env.USERPROFILE = dir;
  process.env.APPDATA = path.join(dir, "AppData", "Roaming");
  try {
    const target = path.join(dir, ".codex", "AGENTS.md");
    const oldBlock = [
      "---- START OF DOCDEX INFO V0.2.17 ----",
      "OLD DOCDEX INSTRUCTIONS",
      "---- END OF DOCDEX INFO -----"
    ].join("\n");
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, `Some other rules\n\n${oldBlock}\n\nKeep this line\n`);
    const result = applyAgentInstructions({ logger: { warn: () => {} } });
    assert.equal(result.ok, true);
    const contents = fs.readFileSync(target, "utf8");
    assert.ok(contents.includes("Some other rules"));
    assert.ok(contents.includes("Keep this line"));
    assert.ok(!contents.includes("OLD DOCDEX INSTRUCTIONS"));
    assert.ok(!contents.includes("V0.2.17"));
    assert.ok(contents.includes(`---- START OF DOCDEX INFO V${PACKAGE_VERSION} ----`));
    assert.ok(contents.includes("---- END OF DOCDEX INFO -----"));
  } finally {
    process.env.HOME = prev.HOME;
    process.env.USERPROFILE = prev.USERPROFILE;
    process.env.APPDATA = prev.APPDATA;
  }
});

test("runPostInstallSetup does not call Ollama installers", () => {
  const source = runPostInstallSetup.toString();
  assert.equal(source.includes("maybeInstallOllama"), false);
  assert.equal(source.includes("maybePromptOllamaModel"), false);
});

test("runPostInstallSetup describes local LLM service choice before Ollama fallback", () => {
  const source = runPostInstallSetup.toString();
  assert.equal(source.includes("existing local LLM services"), true);
  assert.equal(source.includes("Ollama fallback"), true);
  assert.equal(source.includes('setup: "local_llm_service_choice"'), true);
});

test("resolveDaemonPortState reuses existing daemon when port busy and healthy", async () => {
  let cleared = false;
  const state = await resolveDaemonPortState({
    host: "127.0.0.1",
    port: 28491,
    logger: { warn: () => {} },
    deps: {
      isPortAvailable: async () => false,
      stopDaemonService: () => {},
      stopDaemonFromLock: () => {},
      stopDaemonByName: () => {},
      clearDaemonLocks: () => {
        cleared = true;
      },
      sleep: async () => {},
      checkDaemonHealth: async () => true,
      checkDocdexIdentity: async () => false,
      readDaemonLockMetadataForPort: () => null,
      isPidRunning: () => false
    }
  });
  assert.equal(state.available, false);
  assert.equal(state.reuseExisting, true);
  assert.equal(cleared, false);
});

test("resolveDaemonPortState reports busy when port in use by non-docdex", async () => {
  const state = await resolveDaemonPortState({
    host: "127.0.0.1",
    port: 28491,
    deps: {
      isPortAvailable: async () => false,
      stopDaemonService: () => {},
      stopDaemonFromLock: () => {},
      stopDaemonByName: () => {},
      clearDaemonLocks: () => {},
      sleep: async () => {},
      checkDaemonHealth: async () => false,
      checkDocdexIdentity: async () => false,
      readDaemonLockMetadataForPort: () => null,
      isPidRunning: () => false
    }
  });
  assert.equal(state.available, false);
  assert.equal(state.reuseExisting, false);
});

test("resolveDaemonPortState reports starting when lock pid is running but health is not ready", async () => {
  const warnings = [];
  const state = await resolveDaemonPortState({
    host: "127.0.0.1",
    port: 28491,
    logger: { warn: (message) => warnings.push(message) },
    deps: {
      isPortAvailable: async () => false,
      stopDaemonService: () => {},
      stopDaemonFromLock: () => {},
      stopDaemonByName: () => {},
      clearDaemonLocks: () => {},
      sleep: async () => {},
      checkDaemonHealth: async () => false,
      checkDocdexIdentity: async () => false,
      readDaemonLockMetadataForPort: () => ({ pid: 1234, port: 28491 }),
      isPidRunning: () => true
    }
  });
  assert.equal(state.available, false);
  assert.equal(state.reuseExisting, true);
  assert.equal(state.starting, true);
  assert.ok(warnings.some((message) => message.includes("still starting")));
});

test("startDaemonWithHealthCheck relies on registerStartup for startNow", async () => {
  const calls = [];
  const result = await startDaemonWithHealthCheck({
    binaryPath: "/tmp/docdexd",
    host: "127.0.0.1",
    port: 28491,
    deps: {
      registerStartup: (options) => {
        calls.push({ type: "registerStartup", options });
        return { ok: true };
      },
      waitForDaemonReady: async (options) => {
        calls.push({ type: "waitForDaemonReady", options });
        return true;
      },
      stopDaemonService: () => {
        calls.push({ type: "stopDaemonService" });
      },
      stopDaemonFromLock: () => {
        calls.push({ type: "stopDaemonFromLock" });
      },
      stopDaemonByName: () => {
        calls.push({ type: "stopDaemonByName" });
      },
      clearDaemonLocks: () => {
        calls.push({ type: "clearDaemonLocks" });
      }
    }
  });
  assert.deepEqual(
    calls.map((entry) => entry.type),
    ["registerStartup", "waitForDaemonReady"]
  );
  assert.equal(calls[0].options.startNow, true);
  assert.equal(result.ok, true);
  assert.equal(result.reason, "ready");
});

test("startDaemonWithHealthCheck cleans up after health failure", async () => {
  const calls = [];
  const result = await startDaemonWithHealthCheck({
    binaryPath: "/tmp/docdexd",
    host: "127.0.0.1",
    port: 28491,
    deps: {
      registerStartup: () => ({ ok: true }),
      waitForDaemonReady: async () => false,
      stopDaemonService: () => {
        calls.push("stopDaemonService");
      },
      stopDaemonFromLock: () => {
        calls.push("stopDaemonFromLock");
      },
      stopDaemonByName: () => {
        calls.push("stopDaemonByName");
      },
      clearDaemonLocks: () => {
        calls.push("clearDaemonLocks");
      }
    }
  });
  assert.equal(result.ok, false);
  assert.equal(result.reason, "readiness_failed");
  assert.deepEqual(calls, [
    "stopDaemonService",
    "stopDaemonFromLock",
    "stopDaemonByName",
    "clearDaemonLocks"
  ]);
});

test("startDaemonWithHealthCheck can wait for reused daemon readiness without starting", async () => {
  const calls = [];
  const result = await startDaemonWithHealthCheck({
    binaryPath: "/tmp/docdexd",
    host: "127.0.0.1",
    port: 28491,
    startNow: false,
    waitForReady: true,
    deps: {
      registerStartup: (options) => {
        calls.push({ type: "registerStartup", options });
        return { ok: true };
      },
      waitForDaemonReady: async (options) => {
        calls.push({ type: "waitForDaemonReady", options });
        return true;
      }
    }
  });
  assert.deepEqual(
    calls.map((entry) => entry.type),
    ["registerStartup", "waitForDaemonReady"]
  );
  assert.equal(calls[0].options.startNow, false);
  assert.equal(result.ok, true);
  assert.equal(result.reason, "ready");
});

test("waitForDaemonReady requires both health and MCP route readiness", async () => {
  const calls = [];
  const ready = await waitForDaemonReady({
    host: "127.0.0.1",
    port: 28491,
    timeoutMs: 50,
    deps: {
      checkDaemonHealth: async () => {
        calls.push("health");
        return true;
      },
      checkDaemonMcpReady: async () => {
        calls.push("mcp");
        return true;
      },
      sleep: async () => {}
    }
  });
  assert.equal(ready, true);
  assert.deepEqual(calls, ["health", "mcp"]);
});

test("normalizeVersion strips v prefix and trims whitespace", () => {
  assert.equal(normalizeVersion("v0.2.29"), "0.2.29");
  assert.equal(normalizeVersion(" 0.2.29 "), "0.2.29");
  assert.equal(normalizeVersion("V0.2.29"), "0.2.29");
});

test("buildDaemonEnv includes base daemon env values", () => {
  const env = buildDaemonEnv({
    env: { DOCDEX_ENABLE_STANDALONE_MCP: "1" }
  });
  assert.equal(env.DOCDEX_BROWSER_AUTO_INSTALL, "0");
  assert.equal(env.DOCDEX_REPO_IDLE_SECONDS, "300");
  assert.equal(env.DOCDEX_REPO_HIBERNATE_SECONDS, "1800");
  assert.equal(env.DOCDEX_REPO_CLEANUP_INTERVAL_SECONDS, "60");
  assert.equal(env.DOCDEX_WEB_MAX_CONCURRENT_BROWSER_FETCHES, "1");
  assert.equal(env.DOCDEX_WEB_MAX_CONCURRENT_LLM, "1");
  assert.equal(env.DOCDEX_MCP_SERVER_BIN, undefined);
});

test("buildLaunchAgentPlist includes NumberOfFiles soft/hard limits", () => {
  const plist = buildLaunchAgentPlist({
    programArgs: ["/tmp/docdexd", "daemon"],
    envPairs: [["DOCDEX_BROWSER_AUTO_INSTALL", "0"]],
    workingDir: "/tmp/docdex",
    logDir: "/tmp/docdex/logs"
  });
  assert.ok(plist.includes("<key>SoftResourceLimits</key>"));
  assert.ok(plist.includes("<key>HardResourceLimits</key>"));
  assert.ok(plist.includes("<key>NumberOfFiles</key>"));
  assert.ok(plist.includes("<integer>65536</integer>"));
  assert.ok(plist.includes("<integer>200000</integer>"));
  assert.ok(plist.includes("<key>RunAtLoad</key>"));
  assert.ok(plist.includes("<key>KeepAlive</key>"));
  assert.ok(plist.includes("daemon.out.log"));
  assert.ok(plist.includes("daemon.err.log"));
});

test("resolveOllamaInstallMode respects env overrides", () => {
  const mode = resolveOllamaInstallMode({
    env: { DOCDEX_OLLAMA_INSTALL: "1" },
    stdin: {},
    stdout: {}
  });
  assert.equal(mode.mode, "install");
});

test("resolveOllamaInstallMode skips when non-interactive", () => {
  const mode = resolveOllamaInstallMode({
    env: {},
    stdin: { isTTY: false },
    stdout: { isTTY: false },
    canPrompt: () => false
  });
  assert.equal(mode.mode, "skip");
});

test("resolveOllamaInstallMode prompts when interactive", () => {
  const mode = resolveOllamaInstallMode({
    env: {},
    stdin: { isTTY: true },
    stdout: { isTTY: true },
    canPrompt: () => true
  });
  assert.equal(mode.mode, "prompt");
});

test("resolveOllamaInstallMode prompts even when CI if promptable", () => {
  const mode = resolveOllamaInstallMode({
    env: { CI: "1" },
    stdin: { isTTY: true },
    stdout: { isTTY: true },
    canPrompt: () => true
  });
  assert.equal(mode.mode, "prompt");
});

test("resolveOllamaModelPromptMode auto-accepts with env flag", () => {
  const mode = resolveOllamaModelPromptMode({
    env: { DOCDEX_OLLAMA_MODEL_ASSUME_Y: "1" },
    stdin: {},
    stdout: {},
    canPrompt: () => false
  });
  assert.equal(mode.mode, "auto");
});

test("hasInteractiveTty accepts stdout-only TTY", () => {
  assert.equal(hasInteractiveTty({ isTTY: false }, { isTTY: true }), true);
});

test("resolveOllamaModelPromptMode skips when disabled", () => {
  const mode = resolveOllamaModelPromptMode({
    env: { DOCDEX_OLLAMA_MODEL_PROMPT: "0" },
    stdin: { isTTY: true },
    stdout: { isTTY: true },
    canPrompt: () => true
  });
  assert.equal(mode.mode, "skip");
});

test("resolveOllamaModelPromptMode prompts even when CI if promptable", () => {
  const mode = resolveOllamaModelPromptMode({
    env: { CI: "1" },
    stdin: { isTTY: true },
    stdout: { isTTY: true },
    canPrompt: () => true
  });
  assert.equal(mode.mode, "prompt");
});

test("shouldSkipSetup returns true when DOCDEX_SETUP_SKIP is set", () => {
  assert.equal(shouldSkipSetup({ DOCDEX_SETUP_SKIP: "1" }), true);
  assert.equal(shouldSkipSetup({ DOCDEX_SETUP_SKIP: "true" }), true);
  assert.equal(shouldSkipSetup({ DOCDEX_SETUP_SKIP: "0" }), false);
});

test("launchSetupWizard uses linux terminal launcher when interactive", () => {
  const calls = [];
  const spawnFn = (cmd, args, opts) => {
    calls.push({ cmd, args, opts });
    return { pid: 1234, unref() {} };
  };
  const spawnSyncFn = (cmd) => {
    if (cmd === "x-terminal-emulator") return { status: 0 };
    return { error: Object.assign(new Error("missing"), { code: "ENOENT" }) };
  };
  const result = launchSetupWizard({
    binaryPath: "/tmp/docdexd",
    stdin: { isTTY: true },
    stdout: { isTTY: true },
    spawnFn,
    spawnSyncFn,
    platform: "linux"
  });
  assert.equal(result.ok, true);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].cmd, "x-terminal-emulator");
  assert.deepEqual(calls[0].args, [
    "-e",
    "env",
    "DOCDEX_SETUP_AUTO=1",
    "DOCDEX_SETUP_MODE=auto",
    "/tmp/docdexd",
    "setup",
    "--auto"
  ]);
});

test("launchSetupWizard returns non_interactive when no tty", () => {
  const result = launchSetupWizard({
    binaryPath: "/tmp/docdexd",
    stdin: { isTTY: false },
    stdout: { isTTY: false },
    platform: "linux",
    canPrompt: () => false
  });
  assert.equal(result.ok, false);
  assert.equal(result.reason, "non_interactive");
});

test("launchSetupWizard uses osascript on macOS when interactive", () => {
  const calls = [];
  const spawnSyncFn = (cmd, args) => {
    calls.push({ cmd, args });
    return { status: 0 };
  };
  const result = launchSetupWizard({
    binaryPath: "/tmp/docdexd",
    spawnSyncFn,
    platform: "darwin",
    stdin: { isTTY: true },
    stdout: { isTTY: true },
    canPrompt: () => true
  });
  assert.equal(result.ok, true);
  assert.equal(calls[0].cmd, "osascript");
  assert.ok(calls[0].args[0] === "-e");
});

test("launchSetupWizard uses cmd start on Windows", () => {
  const calls = [];
  const spawnSyncFn = (cmd, args) => {
    calls.push({ cmd, args });
    return { status: 0 };
  };
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-setup-runner-"));
  const distBaseDir = path.join(tempDir, "dist");
  const expectedRunner = path.join(tempDir, "run-setup.cmd");
  const result = launchSetupWizard({
    binaryPath: "C:\\\\docdexd.exe",
    spawnSyncFn,
    platform: "win32",
    distBaseDir,
    stdin: { isTTY: true },
    stdout: { isTTY: true },
    canPrompt: () => true
  });
  assert.equal(result.ok, true);
  assert.equal(calls[0].cmd, "cmd");
  assert.deepEqual(calls[0].args.slice(0, 5), ["/c", "start", "", "cmd", "/c"]);
  assert.equal(calls[0].args[5], `"${expectedRunner.replace(/"/g, "\"\"")}"`);
});

test("parseOllamaListOutput extracts model names", () => {
  const output = [
    "NAME            ID              SIZE    MODIFIED",
    "phi3.5:3.8b     abcdef          2.2 GB  2 days ago",
    "nomic-embed-text 123456         274 MB  1 day ago"
  ].join("\n");
  const models = parseOllamaListOutput(output);
  assert.deepEqual(models, ["phi3.5:3.8b", "nomic-embed-text"]);
});

test("formatGiB returns unknown for invalid bytes", () => {
  assert.equal(formatGiB(Number.NaN), "unknown");
  assert.equal(formatGiB(-1), "unknown");
});

test("readLlmDefaultModel detects default model in config", () => {
  const contents = ["[llm]", "default_model = \"phi3.5:3.8b\"", ""].join("\n");
  assert.equal(readLlmDefaultModel(contents), "phi3.5:3.8b");
});

test("upsertLlmDefaultModel adds llm section when missing", () => {
  const contents = ["[server]", "http_bind_addr = \"127.0.0.1:28491\""].join("\n");
  const updated = upsertLlmDefaultModel(contents, "phi3.5:3.8b");
  assert.ok(updated.includes("[llm]"));
  assert.ok(updated.includes("default_model = \"phi3.5:3.8b\""));
});

test("upsertLlmDefaultModel preserves existing default model", () => {
  const contents = ["[llm]", "default_model = \"phi3.5:3.8b\"", ""].join("\n");
  const updated = upsertLlmDefaultModel(contents, "phi3.5:3.8b");
  assert.equal(updated, contents);
});

test("pullOllamaModel invokes ollama pull", () => {
  const calls = [];
  const runner = (cmd, args, opts) => {
    calls.push({ cmd, args, opts });
    return { status: 0, stdout: "", stderr: "" };
  };
  const ok = pullOllamaModel("phi3.5:3.8b", { runner });
  assert.equal(ok, true);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].cmd, "ollama");
  assert.deepEqual(calls[0].args, ["pull", "phi3.5:3.8b"]);
});

test("linux user unit bounds memory and backs off restarts instead of crashlooping", () => {
  const { buildLinuxUserUnit } = require("../lib/postinstall_setup.js");
  const unit = buildLinuxUserUnit({
    binaryPath: "/home/u/.docdex/bin/docdexd",
    args: ["daemon", "--port", "28491"],
    envPairs: [["DOCDEX_ENABLE_MEMORY", "true"]],
    workingDir: "/home/u"
  });

  // A 2s restart with no memory cap turned one OOM kill into an endless loop.
  assert.ok(!unit.includes("RestartSec=2\n"), "restart delay must not be 2s");
  assert.match(unit, /^RestartSec=15$/m);
  assert.match(unit, /^MemoryHigh=2G$/m);
  assert.match(unit, /^MemoryMax=3G$/m);
  // Orphaned headless Chrome accumulated across restarts without this.
  assert.match(unit, /^KillMode=control-group$/m);

  // StartLimit* are [Unit] options; systemd ignores them under [Service].
  const unitSection = unit.slice(unit.indexOf("[Unit]"), unit.indexOf("[Service]"));
  assert.match(unitSection, /^StartLimitIntervalSec=600$/m);
  assert.match(unitSection, /^StartLimitBurst=5$/m);

  // Existing behaviour preserved.
  assert.match(unit, /^ExecStart=\/home\/u\/\.docdex\/bin\/docdexd daemon --port 28491$/m);
  assert.match(unit, /^Environment=DOCDEX_ENABLE_MEMORY=true$/m);
  assert.match(unit, /^WorkingDirectory=\/home\/u$/m);
  assert.match(unit, /^WantedBy=default\.target$/m);
});
