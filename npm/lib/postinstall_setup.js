#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const readline = require("node:readline");
const { spawn, spawnSync } = require("node:child_process");

const { detectPlatformKey, UnsupportedPlatformError } = require("./platform");

const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_PORT_PRIMARY = 3000;
const DEFAULT_PORT_FALLBACK = 3210;
const STARTUP_FAILURE_MARKER = "startup_registration_failed.json";
const DEFAULT_OLLAMA_MODEL = "nomic-embed-text";
const DEFAULT_OLLAMA_CHAT_MODEL = "phi3.5:3.8b";
const DEFAULT_OLLAMA_CHAT_MODEL_SIZE_GIB = 2.2;

function defaultConfigPath() {
  return path.join(os.homedir(), ".docdex", "config.toml");
}

function daemonRootPath() {
  return path.join(os.homedir(), ".docdex", "daemon_root");
}

function stateDir() {
  return path.join(os.homedir(), ".docdex", "state");
}

function configUrlForPort(port) {
  return `http://localhost:${port}/sse`;
}

function isPortAvailable(port, host) {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.unref();
    server.once("error", () => resolve(false));
    server.once("listening", () => {
      server.close(() => resolve(true));
    });
    server.listen(port, host);
  });
}

async function pickAvailablePort(host, preferred) {
  for (const port of preferred) {
    if (await isPortAvailable(port, host)) return port;
  }
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.once("error", reject);
    server.once("listening", () => {
      const addr = server.address();
      server.close(() => resolve(addr.port));
    });
    server.listen(0, host);
  });
}

function parseServerBind(contents) {
  let inServer = false;
  const lines = contents.split(/\r?\n/);
  for (const line of lines) {
    const section = line.match(/^\s*\[([^\]]+)\]\s*$/);
    if (section) {
      inServer = section[1].trim() === "server";
      continue;
    }
    if (!inServer) continue;
    const match = line.match(/^\s*http_bind_addr\s*=\s*["']?([^"']+)["']?/);
    if (match) return match[1].trim();
  }
  return null;
}

function upsertServerConfig(contents, httpBindAddr) {
  const lines = contents.split(/\r?\n/);
  const output = [];
  let inServer = false;
  let foundServer = false;
  let updatedBind = false;
  let updatedEnable = false;

  for (let idx = 0; idx < lines.length; idx += 1) {
    const line = lines[idx];
    const section = line.match(/^\s*\[([^\]]+)\]\s*$/);
    if (section) {
      if (inServer && (!updatedBind || !updatedEnable)) {
        if (!updatedBind) output.push(`http_bind_addr = "${httpBindAddr}"`);
        if (!updatedEnable) output.push("enable_mcp = true");
      }
      inServer = section[1].trim() === "server";
      if (inServer) foundServer = true;
      output.push(line);
      continue;
    }
    if (inServer) {
      if (/^\s*http_bind_addr\s*=/.test(line)) {
        output.push(`http_bind_addr = "${httpBindAddr}"`);
        updatedBind = true;
        continue;
      }
      if (/^\s*enable_mcp\s*=/.test(line)) {
        output.push("enable_mcp = true");
        updatedEnable = true;
        continue;
      }
    }
    output.push(line);
  }

  if (foundServer) {
    if (!updatedBind) output.push(`http_bind_addr = "${httpBindAddr}"`);
    if (!updatedEnable) output.push("enable_mcp = true");
  } else {
    if (output.length && output[output.length - 1].trim()) output.push("");
    output.push("[server]");
    output.push(`http_bind_addr = "${httpBindAddr}"`);
    output.push("enable_mcp = true");
  }

  return output.join("\n");
}

function readJson(pathname) {
  try {
    if (!fs.existsSync(pathname)) return { value: {}, exists: false };
    const raw = fs.readFileSync(pathname, "utf8");
    if (!raw.trim()) return { value: {}, exists: true };
    return { value: JSON.parse(raw), exists: true };
  } catch {
    return { value: {}, exists: true };
  }
}

function writeJson(pathname, value) {
  fs.mkdirSync(path.dirname(pathname), { recursive: true });
  fs.writeFileSync(pathname, JSON.stringify(value, null, 2) + "\n");
}

function upsertMcpServerJson(pathname, url) {
  const { value } = readJson(pathname);
  if (typeof value !== "object" || value == null || Array.isArray(value)) return false;
  const root = value;
  if (!root.mcpServers || typeof root.mcpServers !== "object" || Array.isArray(root.mcpServers)) {
    root.mcpServers = {};
  }
  const current = root.mcpServers.docdex;
  if (current && current.url === url) return false;
  root.mcpServers.docdex = { url };
  writeJson(pathname, root);
  return true;
}

function upsertCodexConfig(pathname, url) {
  let contents = "";
  if (fs.existsSync(pathname)) {
    contents = fs.readFileSync(pathname, "utf8");
  }
  if (/name\s*=\s*\"docdex\"/.test(contents) || /docdex/.test(contents) && /mcp_servers/.test(contents)) {
    return false;
  }
  const block = [
    "",
    "[[mcp_servers]]",
    'name = "docdex"',
    `url = "${url}"`,
    "",
  ].join("\n");
  fs.mkdirSync(path.dirname(pathname), { recursive: true });
  fs.writeFileSync(pathname, contents + block);
  return true;
}

function clientConfigPaths() {
  const home = os.homedir();
  const appData = process.env.APPDATA || path.join(home, "AppData", "Roaming");
  const userProfile = process.env.USERPROFILE || home;
  switch (process.platform) {
    case "win32":
      return {
        claude: path.join(appData, "Claude", "claude_desktop_config.json"),
        cursor: path.join(userProfile, ".cursor", "mcp.json"),
        codex: path.join(userProfile, ".codex", "config.toml")
      };
    case "darwin":
      return {
        claude: path.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
        cursor: path.join(home, ".cursor", "mcp.json"),
        codex: path.join(home, ".codex", "config.toml")
      };
    default:
      return {
        claude: path.join(home, ".config", "Claude", "claude_desktop_config.json"),
        cursor: path.join(home, ".cursor", "mcp.json"),
        codex: path.join(home, ".codex", "config.toml")
      };
  }
}

function resolveBinaryPath({ binaryPath } = {}) {
  if (binaryPath && fs.existsSync(binaryPath)) return binaryPath;
  try {
    const platformKey = detectPlatformKey();
    const candidate = path.join(__dirname, "..", "dist", platformKey, process.platform === "win32" ? "docdexd.exe" : "docdexd");
    if (fs.existsSync(candidate)) return candidate;
  } catch (err) {
    if (!(err instanceof UnsupportedPlatformError)) throw err;
  }
  return null;
}

function ensureDaemonRoot() {
  const root = daemonRootPath();
  fs.mkdirSync(root, { recursive: true });
  const readme = path.join(root, "README.md");
  if (!fs.existsSync(readme)) {
    fs.writeFileSync(readme, "# Docdex daemon root\n");
  }
  return root;
}

function parseEnvBool(value) {
  if (value == null) return null;
  const normalized = String(value).trim().toLowerCase();
  if (["1", "true", "yes", "y", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "n", "off"].includes(normalized)) return false;
  return null;
}

function resolveOllamaInstallMode({ env = process.env, stdin = process.stdin, stdout = process.stdout } = {}) {
  const override = parseEnvBool(env.DOCDEX_OLLAMA_INSTALL);
  if (override === true) return { mode: "install", reason: "env", interactive: false };
  if (override === false) return { mode: "skip", reason: "env", interactive: false };
  const hasTty = Boolean(stdin && stdout && stdin.isTTY && stdout.isTTY);
  if (!hasTty) return { mode: "skip", reason: "non_interactive", interactive: false };
  if (env.CI) return { mode: "skip", reason: "ci", interactive: false };
  return { mode: "prompt", reason: "interactive", interactive: true };
}

function resolveOllamaModelPromptMode({ env = process.env, stdin = process.stdin, stdout = process.stdout } = {}) {
  const override = parseEnvBool(env.DOCDEX_OLLAMA_MODEL_PROMPT);
  if (override === true) return { mode: "prompt", reason: "env", interactive: true };
  if (override === false) return { mode: "skip", reason: "env", interactive: false };
  const assumeYes = parseEnvBool(env.DOCDEX_OLLAMA_MODEL_ASSUME_Y);
  if (assumeYes === true) return { mode: "auto", reason: "env", interactive: false };
  const hasTty = Boolean(stdin && stdout && stdin.isTTY && stdout.isTTY);
  if (!hasTty) return { mode: "skip", reason: "non_interactive", interactive: false };
  if (env.CI) return { mode: "skip", reason: "ci", interactive: false };
  return { mode: "prompt", reason: "interactive", interactive: true };
}

function parseOllamaListOutput(output) {
  const lines = String(output || "").split(/\r?\n/);
  const models = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || /^name\b/i.test(trimmed)) continue;
    const name = trimmed.split(/\s+/)[0];
    if (name) models.push(name);
  }
  return models;
}

function listOllamaModels({ runner = spawnSync } = {}) {
  const result = runner("ollama", ["list"], { stdio: "pipe" });
  if (result.error || result.status !== 0) return null;
  return parseOllamaListOutput(result.stdout);
}

function formatGiB(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return "unknown";
  return `${(bytes / 1024 / 1024 / 1024).toFixed(1)} GiB`;
}

function getDiskFreeBytesUnix() {
  if (typeof fs.statfsSync !== "function") return null;
  try {
    const stats = fs.statfsSync(os.homedir());
    return Number(stats.bavail) * Number(stats.bsize);
  } catch {
    try {
      const stats = fs.statfsSync("/");
      return Number(stats.bavail) * Number(stats.bsize);
    } catch {
      return null;
    }
  }
}

function parsePowerShellFreeBytes(output) {
  const trimmed = String(output || "").trim();
  const value = Number.parseFloat(trimmed);
  return Number.isFinite(value) ? value : null;
}

function parseWmicFreeBytes(output) {
  const lines = String(output || "").split(/\r?\n/);
  for (const line of lines) {
    const match = line.match(/FreeSpace=(\d+)/i);
    if (match) return Number(match[1]);
  }
  return null;
}

function getDiskFreeBytesWindows() {
  if (isCommandAvailable("powershell", ["-NoProfile", "-Command", "$PSVersionTable.PSVersion.Major"])) {
    const result = spawnSync(
      "powershell",
      [
        "-NoProfile",
        "-Command",
        "(Get-PSDrive -Name $env:SystemDrive.TrimEnd(':')).Free"
      ],
      { stdio: "pipe" }
    );
    const parsed = parsePowerShellFreeBytes(result.stdout);
    if (parsed != null) return parsed;
  }
  if (isCommandAvailable("wmic", ["/?"])) {
    const drive = (process.env.SystemDrive || "C:").toUpperCase();
    const result = spawnSync(
      "wmic",
      ["logicaldisk", "where", `DeviceID='${drive}'`, "get", "FreeSpace", "/value"],
      { stdio: "pipe" }
    );
    return parseWmicFreeBytes(result.stdout);
  }
  return null;
}

function getDiskFreeBytes() {
  if (process.platform === "win32") return getDiskFreeBytesWindows();
  return getDiskFreeBytesUnix();
}

function normalizeModelName(name) {
  return String(name || "").trim();
}

function readLlmDefaultModel(contents) {
  let inLlm = false;
  const lines = String(contents || "").split(/\r?\n/);
  for (const line of lines) {
    const section = line.match(/^\s*\[([^\]]+)\]\s*$/);
    if (section) {
      inLlm = section[1].trim() === "llm";
      continue;
    }
    if (!inLlm) continue;
    const match = line.match(/^\s*default_model\s*=\s*\"([^\"]+)\"/);
    if (match) return match[1];
  }
  return null;
}

function upsertLlmDefaultModel(contents, model) {
  const lines = String(contents || "").split(/\r?\n/);
  const output = [];
  let inLlm = false;
  let foundLlm = false;
  let updated = false;

  for (const line of lines) {
    const section = line.match(/^\s*\[([^\]]+)\]\s*$/);
    if (section) {
      if (inLlm && !updated) {
        output.push(`default_model = \"${model}\"`);
        updated = true;
      }
      inLlm = section[1].trim() === "llm";
      if (inLlm) foundLlm = true;
      output.push(line);
      continue;
    }
    if (inLlm) {
      if (/^\s*default_model\s*=/.test(line)) {
        output.push(`default_model = \"${model}\"`);
        updated = true;
        continue;
      }
    }
    output.push(line);
  }

  if (foundLlm) {
    if (!updated) output.push(`default_model = \"${model}\"`);
  } else {
    if (output.length && output[output.length - 1].trim()) output.push("");
    output.push("[llm]");
    output.push(`default_model = \"${model}\"`);
  }
  return output.join("\n");
}

function isCommandAvailable(command, args = ["--version"]) {
  const result = spawnSync(command, args, { stdio: "ignore" });
  if (result.error) return false;
  return true;
}

function isOllamaAvailable() {
  return isCommandAvailable("ollama", ["--version"]);
}

function promptYesNo(question, { defaultYes = true, stdin = process.stdin, stdout = process.stdout } = {}) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: stdin, output: stdout });
    rl.question(question, (answer) => {
      rl.close();
      const normalized = String(answer || "").trim().toLowerCase();
      if (!normalized) return resolve(defaultYes);
      resolve(["y", "yes"].includes(normalized));
    });
  });
}

function promptInput(question, { stdin = process.stdin, stdout = process.stdout } = {}) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: stdin, output: stdout });
    rl.question(question, (answer) => {
      rl.close();
      resolve(String(answer || "").trim());
    });
  });
}

function runInstallCommand(command, args, { logger, interactive } = {}) {
  const options = { stdio: interactive ? "inherit" : "pipe" };
  const result = spawnSync(command, args, options);
  if (result.error) {
    logger?.warn?.(`[docdex] ${command} failed: ${result.error.message || result.error}`);
    return false;
  }
  if (result.status !== 0) {
    const stderr = result.stderr ? String(result.stderr).trim() : "";
    logger?.warn?.(`[docdex] ${command} exited with ${result.status}${stderr ? `: ${stderr}` : ""}`);
    return false;
  }
  return true;
}

function installOllama({ logger, interactive } = {}) {
  if (process.platform === "darwin") {
    if (!isCommandAvailable("brew")) {
      logger?.warn?.("[docdex] Homebrew not found; install Ollama from https://ollama.com/download");
      return false;
    }
    return runInstallCommand("brew", ["install", "ollama"], { logger, interactive });
  }
  if (process.platform === "linux") {
    if (isCommandAvailable("curl")) {
      return runInstallCommand("sh", ["-c", "curl -fsSL https://ollama.com/install.sh | sh"], {
        logger,
        interactive
      });
    }
    if (isCommandAvailable("wget")) {
      return runInstallCommand("sh", ["-c", "wget -qO- https://ollama.com/install.sh | sh"], {
        logger,
        interactive
      });
    }
    logger?.warn?.("[docdex] curl or wget not found; install Ollama from https://ollama.com/download");
    return false;
  }
  if (process.platform === "win32") {
    if (!isCommandAvailable("winget", ["--version"])) {
      logger?.warn?.("[docdex] winget not found; install Ollama from https://ollama.com/download");
      return false;
    }
    return runInstallCommand(
      "winget",
      ["install", "-e", "--id", "Ollama.Ollama", "--accept-package-agreements", "--accept-source-agreements"],
      { logger, interactive }
    );
  }
  logger?.warn?.("[docdex] unsupported platform; install Ollama from https://ollama.com/download");
  return false;
}

function pullOllamaModel(model, { logger, interactive, runner = spawnSync } = {}) {
  const result = runner("ollama", ["pull", model], { stdio: interactive ? "inherit" : "pipe" });
  if (result.error) {
    logger?.warn?.(`[docdex] ollama pull failed: ${result.error.message || result.error}`);
    return false;
  }
  if (result.status !== 0) {
    const stderr = result.stderr ? String(result.stderr).trim() : "";
    logger?.warn?.(`[docdex] ollama pull exited with ${result.status}${stderr ? `: ${stderr}` : ""}`);
    return false;
  }
  return true;
}

async function maybeInstallOllama({ logger, env = process.env, stdin = process.stdin, stdout = process.stdout } = {}) {
  if (isOllamaAvailable()) return { status: "available" };
  const decision = resolveOllamaInstallMode({ env, stdin, stdout });
  if (decision.mode === "skip") return { status: "skipped", reason: decision.reason };
  if (decision.mode === "prompt") {
    const answer = await promptYesNo(
      `[docdex] Ollama not found. Install Ollama and ${DEFAULT_OLLAMA_MODEL}? [Y/n] `,
      { defaultYes: true, stdin, stdout }
    );
    if (!answer) {
      logger?.warn?.("[docdex] Skipping Ollama install. Run `docdexd llm-setup` later if needed.");
      return { status: "declined" };
    }
  }
  logger?.warn?.("[docdex] Installing Ollama...");
  const installed = installOllama({ logger, interactive: decision.interactive });
  if (!installed) {
    logger?.warn?.("[docdex] Ollama install failed; see https://ollama.com/download");
    return { status: "failed" };
  }
  if (!isOllamaAvailable()) {
    logger?.warn?.("[docdex] Ollama installed but not found on PATH. Restart your shell.");
    return { status: "failed" };
  }
  const model = String(env.DOCDEX_OLLAMA_MODEL || DEFAULT_OLLAMA_MODEL).trim() || DEFAULT_OLLAMA_MODEL;
  const pulled = pullOllamaModel(model, { logger, interactive: decision.interactive });
  if (!pulled) {
    logger?.warn?.(`[docdex] Ollama installed but model pull failed. Run: ollama pull ${model}`);
    return { status: "partial" };
  }
  logger?.warn?.(`[docdex] Ollama ready with model ${model}.`);
  return { status: "installed" };
}

function updateDefaultModelConfig(configPath, model, logger) {
  if (!configPath) return false;
  const normalized = normalizeModelName(model);
  if (!normalized) return false;
  let contents = "";
  if (fs.existsSync(configPath)) {
    contents = fs.readFileSync(configPath, "utf8");
  }
  const current = normalizeModelName(readLlmDefaultModel(contents));
  if (current && current === normalized) return false;
  const next = upsertLlmDefaultModel(contents, normalized);
  fs.mkdirSync(path.dirname(configPath), { recursive: true });
  fs.writeFileSync(configPath, next);
  logger?.warn?.(`[docdex] set default model to ${normalized} in ${configPath}`);
  return true;
}

async function maybePromptOllamaModel({
  logger,
  configPath,
  env = process.env,
  stdin = process.stdin,
  stdout = process.stdout
} = {}) {
  if (!isOllamaAvailable()) return { status: "skipped", reason: "ollama_missing" };

  const forced = normalizeModelName(env.DOCDEX_OLLAMA_MODEL);
  if (forced) {
    const installed = listOllamaModels() || [];
    const forcedLower = forced.toLowerCase();
    const hasForced = installed.some((model) => normalizeModelName(model).toLowerCase() === forcedLower);
    if (!hasForced) {
      const pulled = pullOllamaModel(forced, { logger, interactive: false });
      if (!pulled) return { status: "failed", reason: "pull_failed" };
    }
    updateDefaultModelConfig(configPath, forced, logger);
    return { status: "forced", model: forced };
  }

  const decision = resolveOllamaModelPromptMode({ env, stdin, stdout });
  if (decision.mode === "skip") return { status: "skipped", reason: decision.reason };

  const installed = listOllamaModels();
  if (!installed) {
    logger?.warn?.("[docdex] ollama list failed; skipping model prompt");
    return { status: "skipped", reason: "list_failed" };
  }

  const phiModel = DEFAULT_OLLAMA_CHAT_MODEL;
  const freeBytes = getDiskFreeBytes();
  const freeText = formatGiB(freeBytes);
  const sizeText = `${DEFAULT_OLLAMA_CHAT_MODEL_SIZE_GIB.toFixed(1)} GB`;

  const configContents = fs.existsSync(configPath) ? fs.readFileSync(configPath, "utf8") : "";
  const configDefault = normalizeModelName(readLlmDefaultModel(configContents));
  const envDefault = normalizeModelName(env.DOCDEX_OLLAMA_DEFAULT_MODEL);
  const defaultChoice = envDefault || configDefault || null;

  if (installed.length === 0) {
    if (decision.mode === "auto") {
      const pulled = pullOllamaModel(phiModel, { logger, interactive: false });
      if (!pulled) return { status: "failed", reason: "pull_failed" };
      updateDefaultModelConfig(configPath, phiModel, logger);
      return { status: "installed", model: phiModel };
    }
    stdout.write(
      `[docdex] Ollama has no models installed. Free space: ${freeText}. ` +
        `${phiModel} uses ~${sizeText}.\n`
    );
    const accept = await promptYesNo(
      `[docdex] Install ${phiModel} now? [Y/n] `,
      { defaultYes: true, stdin, stdout }
    );
    if (!accept) return { status: "declined" };
    const pulled = pullOllamaModel(phiModel, { logger, interactive: true });
    if (!pulled) return { status: "failed", reason: "pull_failed" };
    updateDefaultModelConfig(configPath, phiModel, logger);
    return { status: "installed", model: phiModel };
  }

  const normalizedInstalled = installed.map(normalizeModelName);
  const installedLower = normalizedInstalled.map((model) => model.toLowerCase());
  const hasPhi = installedLower.includes(phiModel.toLowerCase());
  const selectionDefault = defaultChoice && installedLower.includes(defaultChoice.toLowerCase())
    ? defaultChoice
    : normalizedInstalled[0];

  if (decision.mode === "auto") {
    if (selectionDefault) {
      updateDefaultModelConfig(configPath, selectionDefault, logger);
      return { status: "selected", model: selectionDefault };
    }
    return { status: "skipped", reason: "no_models" };
  }

  stdout.write("[docdex] Ollama models detected:\n");
  normalizedInstalled.forEach((model, idx) => {
    const marker = model === selectionDefault ? " (default)" : "";
    stdout.write(`  ${idx + 1}) ${model}${marker}\n`);
  });
  if (!hasPhi) {
    stdout.write(`  I) Install ${phiModel} (~${sizeText}, free ${freeText})\n`);
  }
  stdout.write("  S) Skip\n");

  const answer = await promptInput(
    `[docdex] Select default model [${selectionDefault}]: `,
    { stdin, stdout }
  );
  const normalizedAnswer = normalizeModelName(answer);
  const answerLower = normalizedAnswer.toLowerCase();
  if (!answer) {
    updateDefaultModelConfig(configPath, selectionDefault, logger);
    return { status: "selected", model: selectionDefault };
  }
  if (answerLower === "s" || answerLower === "skip") {
    return { status: "skipped", reason: "user_skip" };
  }
  if ((answerLower === "i" || answerLower === "install") && !hasPhi) {
    const pulled = pullOllamaModel(phiModel, { logger, interactive: true });
    if (!pulled) return { status: "failed", reason: "pull_failed" };
    updateDefaultModelConfig(configPath, phiModel, logger);
    return { status: "installed", model: phiModel };
  }
  const numeric = Number.parseInt(answerLower, 10);
  if (Number.isFinite(numeric) && numeric >= 1 && numeric <= normalizedInstalled.length) {
    const selected = normalizedInstalled[numeric - 1];
    updateDefaultModelConfig(configPath, selected, logger);
    return { status: "selected", model: selected };
  }
  const matchedIndex = installedLower.indexOf(answerLower);
  if (matchedIndex !== -1) {
    const selected = normalizedInstalled[matchedIndex];
    updateDefaultModelConfig(configPath, selected, logger);
    return { status: "selected", model: selected };
  }
  logger?.warn?.("[docdex] Unrecognized selection; skipping model update.");
  return { status: "skipped", reason: "invalid_selection" };
}

function registerStartup({ binaryPath, port, repoRoot, logger }) {
  if (!binaryPath) return { ok: false, reason: "missing_binary" };
  const args = [
    "daemon",
    "--repo",
    repoRoot,
    "--host",
    DEFAULT_HOST,
    "--port",
    String(port),
    "--log",
    "warn",
    "--secure-mode=false"
  ];

  if (process.platform === "darwin") {
    const plistPath = path.join(os.homedir(), "Library", "LaunchAgents", "com.docdex.daemon.plist");
    const logDir = path.join(os.homedir(), ".docdex", "logs");
    fs.mkdirSync(logDir, { recursive: true });
    const programArgs = [binaryPath, ...args];
    const plist = `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n` +
      `<plist version="1.0">\n` +
      `<dict>\n` +
      `  <key>Label</key>\n` +
      `  <string>com.docdex.daemon</string>\n` +
      `  <key>ProgramArguments</key>\n` +
      `  <array>\n` +
      programArgs.map((arg) => `    <string>${arg}</string>\n`).join("") +
      `  </array>\n` +
      `  <key>RunAtLoad</key>\n` +
      `  <true/>\n` +
      `  <key>KeepAlive</key>\n` +
      `  <true/>\n` +
      `  <key>StandardOutPath</key>\n` +
      `  <string>${path.join(logDir, "daemon.out.log")}</string>\n` +
      `  <key>StandardErrorPath</key>\n` +
      `  <string>${path.join(logDir, "daemon.err.log")}</string>\n` +
      `</dict>\n` +
      `</plist>\n`;
    fs.mkdirSync(path.dirname(plistPath), { recursive: true });
    fs.writeFileSync(plistPath, plist);
    const uid = typeof process.getuid === "function" ? process.getuid() : null;
    const bootstrap = uid != null
      ? spawnSync("launchctl", ["bootstrap", `gui/${uid}`, plistPath])
      : spawnSync("launchctl", ["load", "-w", plistPath]);
    if (bootstrap.status === 0) return { ok: true };
    const fallback = spawnSync("launchctl", ["load", "-w", plistPath]);
    if (fallback.status === 0) return { ok: true };
    logger?.warn?.(`[docdex] launchctl failed: ${bootstrap.stderr || fallback.stderr || "unknown error"}`);
    return { ok: false, reason: "launchctl_failed" };
  }

  if (process.platform === "linux") {
    const systemdDir = path.join(os.homedir(), ".config", "systemd", "user");
    const unitPath = path.join(systemdDir, "docdexd.service");
    fs.mkdirSync(systemdDir, { recursive: true });
    const unit = [
      "[Unit]",
      "Description=Docdex daemon",
      "After=network.target",
      "",
      "[Service]",
      `ExecStart=${binaryPath} ${args.join(" ")}`,
      "Restart=always",
      "RestartSec=2",
      "",
      "[Install]",
      "WantedBy=default.target",
      ""
    ].join("\n");
    fs.writeFileSync(unitPath, unit);
    const reload = spawnSync("systemctl", ["--user", "daemon-reload"]);
    const enable = spawnSync("systemctl", ["--user", "enable", "--now", "docdexd.service"]);
    if (reload.status === 0 && enable.status === 0) return { ok: true };
    logger?.warn?.(`[docdex] systemd failed: ${enable.stderr || reload.stderr || "unknown error"}`);
    return { ok: false, reason: "systemd_failed" };
  }

  if (process.platform === "win32") {
    const taskName = "Docdex Daemon";
    const taskArgs = `"${binaryPath}" ${args.map((arg) => `"${arg}"`).join(" ")}`;
    const create = spawnSync("schtasks", [
      "/Create",
      "/F",
      "/SC",
      "ONLOGON",
      "/RL",
      "LIMITED",
      "/TN",
      taskName,
      "/TR",
      taskArgs
    ]);
    if (create.status === 0) {
      spawnSync("schtasks", ["/Run", "/TN", taskName]);
      return { ok: true };
    }
    logger?.warn?.(`[docdex] schtasks failed: ${create.stderr || "unknown error"}`);
    return { ok: false, reason: "schtasks_failed" };
  }

  return { ok: false, reason: "unsupported_platform" };
}

function startDaemonNow({ binaryPath, port, repoRoot }) {
  if (!binaryPath) return false;
  const child = spawn(
    binaryPath,
    [
      "daemon",
      "--repo",
      repoRoot,
      "--host",
      DEFAULT_HOST,
      "--port",
      String(port),
      "--log",
      "warn",
      "--secure-mode=false"
    ],
    { stdio: "ignore", detached: true }
  );
  child.unref();
  return true;
}

function recordStartupFailure(details) {
  const markerPath = path.join(stateDir(), STARTUP_FAILURE_MARKER);
  fs.mkdirSync(path.dirname(markerPath), { recursive: true });
  fs.writeFileSync(markerPath, JSON.stringify(details, null, 2));
}

function clearStartupFailure() {
  const markerPath = path.join(stateDir(), STARTUP_FAILURE_MARKER);
  if (fs.existsSync(markerPath)) fs.unlinkSync(markerPath);
}

function startupFailureReported() {
  return fs.existsSync(path.join(stateDir(), STARTUP_FAILURE_MARKER));
}

async function runPostInstallSetup({ binaryPath, logger } = {}) {
  const log = logger || console;
  const configPath = defaultConfigPath();
  let existingConfig = "";
  if (fs.existsSync(configPath)) {
    existingConfig = fs.readFileSync(configPath, "utf8");
  }
  const configuredBind = existingConfig ? parseServerBind(existingConfig) : null;
  let port;
  if (process.env.DOCDEX_DAEMON_PORT) {
    port = Number(process.env.DOCDEX_DAEMON_PORT);
  } else if (configuredBind) {
    const match = configuredBind.match(/:(\d+)$/);
    port = match ? Number(match[1]) : null;
  }
  if (!port || Number.isNaN(port)) {
    port = await pickAvailablePort(DEFAULT_HOST, [DEFAULT_PORT_PRIMARY, DEFAULT_PORT_FALLBACK]);
  }

  const httpBindAddr = `${DEFAULT_HOST}:${port}`;
  const nextConfig = upsertServerConfig(existingConfig || "", httpBindAddr);
  if (!existingConfig || existingConfig !== nextConfig) {
    fs.mkdirSync(path.dirname(configPath), { recursive: true });
    fs.writeFileSync(configPath, nextConfig);
  }

  const url = configUrlForPort(port);
  const paths = clientConfigPaths();
  upsertMcpServerJson(paths.claude, url);
  upsertMcpServerJson(paths.cursor, url);
  upsertCodexConfig(paths.codex, url);

  const daemonRoot = ensureDaemonRoot();
  const resolvedBinary = resolveBinaryPath({ binaryPath });
  const startup = registerStartup({ binaryPath: resolvedBinary, port, repoRoot: daemonRoot, logger: log });
  if (!startup.ok) {
    if (!startupFailureReported()) {
      log.warn?.("[docdex] startup registration failed; run the daemon manually:");
      log.warn?.(`[docdex]   ${resolvedBinary || "docdexd"} daemon --repo ${daemonRoot} --host ${DEFAULT_HOST} --port ${port}`);
      recordStartupFailure({ reason: startup.reason, port, repoRoot: daemonRoot });
    }
  } else {
    clearStartupFailure();
  }

  startDaemonNow({ binaryPath: resolvedBinary, port, repoRoot: daemonRoot });
  await maybeInstallOllama({ logger: log });
  await maybePromptOllamaModel({ logger: log, configPath });
  return { port, url, configPath };
}

module.exports = {
  runPostInstallSetup,
  upsertServerConfig,
  parseServerBind,
  upsertMcpServerJson,
  upsertCodexConfig,
  pickAvailablePort,
  configUrlForPort,
  parseEnvBool,
  resolveOllamaInstallMode,
  resolveOllamaModelPromptMode,
  parseOllamaListOutput,
  formatGiB,
  readLlmDefaultModel,
  upsertLlmDefaultModel,
  pullOllamaModel,
  listOllamaModels
};
