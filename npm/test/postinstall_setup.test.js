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
  configUrlForPort,
  runPostInstallSetup,
  resolveOllamaInstallMode,
  resolveOllamaModelPromptMode,
  parseOllamaListOutput,
  formatGiB,
  readLlmDefaultModel,
  upsertLlmDefaultModel,
  pullOllamaModel,
  hasInteractiveTty,
  shouldSkipSetup,
  launchSetupWizard
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
  const url = configUrlForPort(3000);
  const changed = upsertCodexConfig(file, url);
  assert.equal(changed, true);
  const contents = fs.readFileSync(file, "utf8");
  assert.ok(!contents.includes("[[mcp_servers]]"));
  assert.ok(contents.includes(`docdex = { url = "${url}" }`) || contents.includes("[mcp_servers.docdex]"));
});

test("runPostInstallSetup does not call Ollama installers", () => {
  const source = runPostInstallSetup.toString();
  assert.equal(source.includes("maybeInstallOllama"), false);
  assert.equal(source.includes("maybePromptOllamaModel"), false);
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
  assert.deepEqual(calls[0].args, ["-e", "/tmp/docdexd", "setup"]);
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
  const contents = ["[server]", "http_bind_addr = \"127.0.0.1:3210\""].join("\n");
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
