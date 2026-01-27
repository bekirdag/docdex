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
  configUrlForPort,
  configStreamableUrlForPort,
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
  buildDaemonEnv
} = require("../lib/postinstall_setup");

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

test("upsertZedConfig sets experimental_mcp_servers", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-zed-"));
  const file = path.join(dir, "settings.json");
  const url = configUrlForPort(3000);
  const changed = upsertZedConfig(file, url);
  assert.equal(changed, true);
  const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.equal(parsed.experimental_mcp_servers.docdex.url, url);
});

test("upsertCodexConfig appends docdex server", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-codex-"));
  const file = path.join(dir, "config.toml");
  const url = configStreamableUrlForPort(28491);
  const changed = upsertCodexConfig(file, url);
  assert.equal(changed, true);
  const contents = fs.readFileSync(file, "utf8");
  assert.ok(contents.includes("[mcp_servers]"));
  assert.ok(contents.includes(`docdex = { url = "${url}" }`));
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
  assert.ok(contents.includes(`docdex = { url = "${url}" }`) || contents.includes("[mcp_servers.docdex]"));
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
  assert.equal(env.DOCDEX_MCP_SERVER_BIN, undefined);
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
  const result = launchSetupWizard({
    binaryPath: "C:\\\\docdexd.exe",
    spawnSyncFn,
    platform: "win32"
  });
  assert.equal(result.ok, true);
  assert.equal(calls[0].cmd, "cmd");
  assert.deepEqual(calls[0].args.slice(0, 2), ["/c", "start"]);
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
