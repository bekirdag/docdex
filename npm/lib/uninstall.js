#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { resolveDocdexDataDir } = require("./paths");

const DAEMON_TASK_NAME = "Docdex Daemon";
const STARTUP_FAILURE_MARKER = "startup_registration_failed.json";
const BIN_NAMES = ["docdex", "docdexd"];
const PACKAGE_NAME = "docdex";
const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_DAEMON_PORT = 28491;
const PORT_WAIT_TIMEOUT_MS = 3000;
const PORT_WAIT_INTERVAL_MS = 200;

function docdexRootPath() {
  return path.join(os.homedir(), ".docdex");
}

function daemonRootPath() {
  return path.join(docdexRootPath(), "daemon_root");
}

function docdexDataDir() {
  return resolveDocdexDataDir({ env: process.env });
}

function stateDir() {
  return path.join(docdexRootPath(), "state");
}

function daemonLockPaths() {
  const paths = [];
  const override = process.env.DOCDEX_DAEMON_LOCK_PATH;
  if (override && override.trim()) paths.push(override.trim());
  const root = docdexRootPath();
  paths.push(path.join(root, "locks", "daemon.lock"));
  paths.push(path.join(root, "daemon.lock"));
  return Array.from(new Set(paths));
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

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function sleepSync(ms) {
  if (!ms || ms <= 0) return;
  const buffer = new SharedArrayBuffer(4);
  const view = new Int32Array(buffer);
  Atomics.wait(view, 0, 0, ms);
}

function isPidRunning(pid) {
  if (!pid) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function readLockMetadata(lockPath) {
  if (!lockPath || !fs.existsSync(lockPath)) return null;
  try {
    const raw = fs.readFileSync(lockPath, "utf8");
    const payload = JSON.parse(raw);
    if (!payload || typeof payload !== "object") return null;
    const pid = typeof payload.pid === "number" ? payload.pid : null;
    const port = typeof payload.port === "number" ? payload.port : null;
    return { pid, port, lockPath };
  } catch {
    return null;
  }
}

function findRunningDaemonFromLocks() {
  for (const lockPath of daemonLockPaths()) {
    const meta = readLockMetadata(lockPath);
    if (!meta) continue;
    if (isPidRunning(meta.pid)) return meta;
  }
  return null;
}

function manualStopInstructions() {
  if (process.platform === "darwin") {
    const uid = typeof process.getuid === "function" ? process.getuid() : null;
    const domain = uid != null ? `gui/${uid}` : "gui/$UID";
    return [
      "Manual cleanup required:",
      `- launchctl bootout ${domain} ~/Library/LaunchAgents/com.docdex.daemon.plist`,
      "- launchctl remove com.docdex.daemon",
      "- pkill -f docdexd",
      "- rm -f ~/.docdex/locks/daemon.lock",
      "- lsof -iTCP:28491 -sTCP:LISTEN",
    ];
  }
  if (process.platform === "win32") {
    const dataDir = docdexDataDir();
    return [
      "Manual cleanup required:",
      `- schtasks /End /TN "${DAEMON_TASK_NAME}"`,
      "- schtasks /Delete /TN \"Docdex Daemon\" /F",
      "- taskkill /IM docdexd.exe /T /F",
      "- del %USERPROFILE%\\.docdex\\locks\\daemon.lock",
      `- del "${path.join(dataDir, "run-daemon.cmd")}"`,
      `- rmdir /S /Q "${dataDir}"`,
      "- netstat -ano | findstr 28491",
    ];
  }
  return [
    "Manual cleanup required:",
    "- systemctl --user stop docdexd.service",
    "- systemctl --user disable --now docdexd.service",
    "- pkill -f docdexd",
    "- rm -f ~/.docdex/locks/daemon.lock",
    "- lsof -iTCP:28491 -sTCP:LISTEN",
  ];
}

async function waitForPortFree({ host = DEFAULT_HOST, port = DEFAULT_DAEMON_PORT } = {}) {
  const deadline = Date.now() + PORT_WAIT_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (await isPortAvailable(port, host)) return true;
    await sleep(PORT_WAIT_INTERVAL_MS);
  }
  return false;
}

function clientConfigPaths() {
  const home = os.homedir();
  const appData = process.env.APPDATA || path.join(home, "AppData", "Roaming");
  const userProfile = process.env.USERPROFILE || home;
  switch (process.platform) {
    case "win32":
      return {
        json: [
          path.join(appData, "Claude", "claude_desktop_config.json"),
          path.join(home, ".claude.json"),
          path.join(userProfile, ".cursor", "mcp.json"),
          path.join(userProfile, ".codeium", "windsurf", "mcp_config.json"),
          path.join(appData, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
          path.join(appData, "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json"),
          path.join(userProfile, ".continue", "config.json"),
          path.join(userProfile, ".kiro", "settings", "mcp.json"),
          path.join(userProfile, ".pearai", "mcp.json"),
          path.join(appData, "Void", "mcp.json"),
          path.join(appData, "Code", "User", "mcp.json"),
          path.join(appData, "Zed", "settings.json")
        ],
        toml: [path.join(userProfile, ".codex", "config.toml")],
        yaml: [path.join(appData, "Aider", "config.yml")]
      };
    case "darwin":
      return {
        json: [
          path.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
          path.join(home, ".claude.json"),
          path.join(home, ".cursor", "mcp.json"),
          path.join(home, ".codeium", "windsurf", "mcp_config.json"),
          path.join(home, "Library", "Application Support", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
          path.join(home, "Library", "Application Support", "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json"),
          path.join(home, ".continue", "config.json"),
          path.join(home, ".kiro", "settings", "mcp.json"),
          path.join(home, ".config", "pearai", "mcp.json"),
          path.join(home, "Library", "Application Support", "Void", "mcp.json"),
          path.join(home, "Library", "Application Support", "Code", "User", "mcp.json"),
          path.join(home, ".config", "zed", "settings.json")
        ],
        toml: [path.join(home, ".codex", "config.toml")],
        yaml: [path.join(home, ".config", "aider", "config.yml"), path.join(home, ".aider.conf.yml")]
      };
    default:
      return {
        json: [
          path.join(home, ".config", "Claude", "claude_desktop_config.json"),
          path.join(home, ".claude.json"),
          path.join(home, ".cursor", "mcp.json"),
          path.join(home, ".codeium", "windsurf", "mcp_config.json"),
          path.join(home, ".config", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
          path.join(home, ".config", "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json"),
          path.join(home, ".continue", "config.json"),
          path.join(home, ".kiro", "settings", "mcp.json"),
          path.join(home, ".config", "pearai", "mcp.json"),
          path.join(home, ".config", "Void", "mcp.json"),
          path.join(home, ".config", "Code", "User", "mcp.json"),
          path.join(home, ".config", "zed", "settings.json")
        ],
        toml: [path.join(home, ".codex", "config.toml")],
        yaml: [path.join(home, ".config", "aider", "config.yml"), path.join(home, ".aider.conf.yml")]
      };
  }
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

function removeMcpServerJson(pathname, name = "docdex") {
  const { value, exists } = readJson(pathname);
  if (!exists || typeof value !== "object" || value == null || Array.isArray(value)) return false;
  const root = value;
  const keys = ["mcpServers", "mcp_servers"];
  let changed = false;
  for (const key of keys) {
    const section = root[key];
    if (!section) continue;
    if (Array.isArray(section)) {
      const before = section.length;
      root[key] = section.filter((entry) => !(entry && entry.name === name));
      if (root[key].length !== before) {
        changed = true;
      }
      if (root[key].length === 0) delete root[key];
      continue;
    }
    if (typeof section !== "object") continue;
    if (Object.prototype.hasOwnProperty.call(section, name)) {
      delete section[name];
      changed = true;
      if (Object.keys(section).length === 0) delete root[key];
    }
  }
  if (
    root.experimental_mcp_servers &&
    typeof root.experimental_mcp_servers === "object" &&
    !Array.isArray(root.experimental_mcp_servers) &&
    Object.prototype.hasOwnProperty.call(root.experimental_mcp_servers, name)
  ) {
    delete root.experimental_mcp_servers[name];
    changed = true;
    if (Object.keys(root.experimental_mcp_servers).length === 0) delete root.experimental_mcp_servers;
  }
  if (!changed) return false;
  writeJson(pathname, root);
  return true;
}

function removeCodexConfig(pathname, name = "docdex") {
  if (!fs.existsSync(pathname)) return false;
  let contents = fs.readFileSync(pathname, "utf8");
  const original = contents;

  const parseTomlString = (value) => {
    const trimmed = value.trim();
    const quoted = trimmed.match(/^"(.*)"$/) || trimmed.match(/^'(.*)'$/);
    return quoted ? quoted[1] : trimmed;
  };

  const removeArrayBlocks = (text) => {
    const lines = text.split(/\r?\n/);
    const output = [];
    let inBlock = false;
    let block = [];
    let blockHasName = false;

    const flush = () => {
      if (!inBlock) return;
      if (!blockHasName) output.push(...block);
      inBlock = false;
      block = [];
      blockHasName = false;
    };

    for (const line of lines) {
      if (/^\s*\[\[mcp_servers\]\]\s*$/.test(line)) {
        flush();
        inBlock = true;
        block = [line];
        continue;
      }
      if (inBlock) {
        if (/^\s*\[.+\]\s*$/.test(line)) {
          flush();
          output.push(line);
          continue;
        }
        const match = line.match(/^\s*name\s*=\s*(.+?)\s*$/);
        if (match && parseTomlString(match[1]) === name) {
          blockHasName = true;
        }
        block.push(line);
        continue;
      }
      output.push(line);
    }
    flush();
    return output.join("\n");
  };

  const removeNestedSection = (text) => {
    const lines = text.split(/\r?\n/);
    const output = [];
    let skip = false;
    for (const line of lines) {
      if (/^\s*\[mcp_servers\.docdex\]\s*$/.test(line)) {
        skip = true;
        continue;
      }
      if (skip) {
        if (/^\s*\[.+\]\s*$/.test(line)) {
          skip = false;
          output.push(line);
        }
        continue;
      }
      output.push(line);
    }
    return output.join("\n");
  };

  const removeTableEntry = (text) => {
    const lines = text.split(/\r?\n/);
    const output = [];
    let inTable = false;
    for (const line of lines) {
      const section = line.match(/^\s*\[([^\]]+)\]\s*$/);
      if (section) {
        inTable = section[1].trim() === "mcp_servers";
        output.push(line);
        continue;
      }
      if (inTable && new RegExp(`^\\s*${name}\\s*=`).test(line)) {
        continue;
      }
      output.push(line);
    }
    return output.join("\n");
  };

  const removeLooseEntry = (text) => {
    const lines = text.split(/\r?\n/);
    const output = [];
    let changed = false;
    for (const line of lines) {
      if (/^\s*docdex\s*=/.test(line)) {
        changed = true;
        continue;
      }
      output.push(line);
    }
    return { text: output.join("\n"), changed };
  };

  const removeEmptyMcpServersTable = (text) => {
    const lines = text.split(/\r?\n/);
    const output = [];
    let inTable = false;
    let tableHasEntries = false;
    let buffer = [];

    const flushTable = () => {
      if (!inTable) return;
      if (tableHasEntries) output.push(...buffer);
      inTable = false;
      tableHasEntries = false;
      buffer = [];
    };

    for (const line of lines) {
      const section = line.match(/^\s*\[([^\]]+)\]\s*$/);
      if (section) {
        flushTable();
        if (section[1].trim() === "mcp_servers") {
          inTable = true;
          buffer = [line];
          continue;
        }
        output.push(line);
        continue;
      }

      if (inTable) {
        if (line.trim() && !line.trim().startsWith("#")) {
          if (/=/.test(line)) tableHasEntries = true;
        }
        buffer.push(line);
        continue;
      }

      output.push(line);
    }
    flushTable();
    return output.join("\n");
  };

  contents = removeArrayBlocks(contents);
  contents = removeNestedSection(contents);
  contents = removeTableEntry(contents);
  const loose = removeLooseEntry(contents);
  contents = loose.text;
  contents = removeEmptyMcpServersTable(contents);

  if (contents !== original) {
    fs.writeFileSync(pathname, contents.endsWith("\n") ? contents : `${contents}\n`);
    return true;
  }
  return false;
}

function removeMcpServerYaml(pathname, name = "docdex") {
  if (!fs.existsSync(pathname)) return false;
  const original = fs.readFileSync(pathname, "utf8");
  const lines = original.split(/\r?\n/);
  const output = [];
  let inSection = false;
  let sectionIndent = null;
  let skipIndent = null;
  let changed = false;

  const indentSize = (line) => (line.match(/^\s*/)?.[0].length ?? 0);

  for (const line of lines) {
    if (skipIndent != null) {
      if (line.trim() && indentSize(line) <= skipIndent) {
        skipIndent = null;
      } else {
        changed = true;
        continue;
      }
    }

    if (!inSection) {
      if (/^\s*mcp_servers\s*:\s*$/.test(line)) {
        inSection = true;
        sectionIndent = indentSize(line);
      }
      output.push(line);
      continue;
    }

    if (line.trim() && indentSize(line) <= sectionIndent) {
      inSection = false;
      output.push(line);
      continue;
    }

    if (new RegExp(`^\\s*${name}\\s*:`).test(line)) {
      changed = true;
      skipIndent = indentSize(line);
      continue;
    }

    const listName = line.match(/^\s*-\s*name\s*:\s*(.+)\s*$/);
    if (listName && listName[1].replace(/["']/g, "").trim() === name) {
      changed = true;
      skipIndent = indentSize(line);
      continue;
    }

    const listValue = line.match(/^\s*-\s*([^\s#]+)\s*$/);
    if (listValue && listValue[1].replace(/["']/g, "").trim() === name) {
      changed = true;
      continue;
    }

    output.push(line);
  }

  if (changed) {
    fs.writeFileSync(pathname, output.join("\n"));
  }
  return changed;
}

function killPid(pid) {
  if (!pid) return false;
  try {
    if (process.platform === "win32") {
      spawnSync("taskkill", ["/PID", String(pid), "/T", "/F"]);
      return true;
    }
    process.kill(pid, "SIGTERM");
    sleepSync(150);
    if (isPidRunning(pid)) {
      process.kill(pid, "SIGKILL");
    }
    return true;
  } catch {
    return false;
  }
}

function stopDaemonFromLock() {
  let stopped = false;
  for (const lockPath of daemonLockPaths()) {
    if (!fs.existsSync(lockPath)) continue;
    try {
      const raw = fs.readFileSync(lockPath, "utf8");
      const payload = JSON.parse(raw);
      const pid = payload && typeof payload.pid === "number" ? payload.pid : null;
      stopped = killPid(pid) || stopped;
      fs.unlinkSync(lockPath);
    } catch {
      continue;
    }
  }
  return stopped;
}


function stopDaemonByName() {
  if (process.platform === "win32") {
    spawnSync("taskkill", ["/IM", "docdexd.exe", "/T", "/F"]);
    return true;
  }
  spawnSync("pkill", ["-TERM", "-x", "docdexd"]);
  spawnSync("pkill", ["-TERM", "-f", "docdexd daemon"]);
  spawnSync("pkill", ["-TERM", "-f", "docdexd serve"]);
  spawnSync("pkill", ["-KILL", "-x", "docdexd"]);
  spawnSync("pkill", ["-KILL", "-f", "docdexd daemon"]);
  spawnSync("pkill", ["-KILL", "-f", "docdexd serve"]);
  return true;
}


function unregisterStartup() {
  if (process.platform === "darwin") {
    const plistPath = path.join(os.homedir(), "Library", "LaunchAgents", "com.docdex.daemon.plist");
    const uid = typeof process.getuid === "function" ? process.getuid() : null;
    const domain = uid != null ? `gui/${uid}` : null;
    if (domain) {
      spawnSync("launchctl", ["bootout", domain, "com.docdex.daemon"]);
    } else {
      spawnSync("launchctl", ["bootout", "com.docdex.daemon"]);
    }
    spawnSync("launchctl", ["stop", "com.docdex.daemon"]);
    if (fs.existsSync(plistPath)) {
      if (domain) {
        spawnSync("launchctl", ["bootout", domain, plistPath]);
      } else {
        spawnSync("launchctl", ["bootout", plistPath]);
      }
      spawnSync("launchctl", ["unload", "-w", plistPath]);
      try {
        fs.unlinkSync(plistPath);
      } catch {}
    }
    spawnSync("launchctl", ["remove", "com.docdex.daemon"]);
    return true;
  }

  if (process.platform === "linux") {
    const systemdDir = path.join(os.homedir(), ".config", "systemd", "user");
    const unitPath = path.join(systemdDir, "docdexd.service");
    spawnSync("systemctl", ["--user", "stop", "docdexd.service"]);
    spawnSync("systemctl", ["--user", "disable", "--now", "docdexd.service"]);
    spawnSync("systemctl", ["--user", "reset-failed", "docdexd.service"]);
    if (fs.existsSync(unitPath)) {
      try {
        fs.unlinkSync(unitPath);
      } catch {}
      spawnSync("systemctl", ["--user", "daemon-reload"]);
    }
    return true;
  }

  if (process.platform === "win32") {
    spawnSync("schtasks", ["/End", "/TN", DAEMON_TASK_NAME]);
    spawnSync("schtasks", ["/Delete", "/TN", DAEMON_TASK_NAME, "/F"]);
    return true;
  }

  return false;
}

function clearStartupFailure() {
  const markerPath = path.join(stateDir(), STARTUP_FAILURE_MARKER);
  if (fs.existsSync(markerPath)) {
    try {
      fs.unlinkSync(markerPath);
    } catch {}
  }
}

function removeDaemonRootNotice() {
  const root = daemonRootPath();
  const readmes = [path.join(root, "README.txt"), path.join(root, "README.md")];
  for (const readme of readmes) {
    if (fs.existsSync(readme)) {
      try {
        fs.unlinkSync(readme);
      } catch {}
    }
  }
}

function removeClientConfigs() {
  const paths = clientConfigPaths();
  for (const pathname of paths.json || []) {
    removeMcpServerJson(pathname);
  }
  for (const pathname of paths.toml || []) {
    removeCodexConfig(pathname);
  }
  for (const pathname of paths.yaml || []) {
    removeMcpServerYaml(pathname);
  }
}

function removeDocdexRootIfEmpty({ fsModule = fs, osModule = os, pathModule = path } = {}) {
  const home = typeof osModule?.homedir === "function" ? osModule.homedir() : os.homedir();
  if (!home) return false;
  const root = pathModule.join(home, ".docdex");
  if (!fsModule.existsSync(root)) return false;
  const resolvedRoot = pathModule.resolve(root);
  const expectedRoot = pathModule.join(pathModule.resolve(home), ".docdex");
  if (resolvedRoot !== expectedRoot) return false;
  let entries = [];
  try {
    entries = fsModule.readdirSync(resolvedRoot);
  } catch {
    return false;
  }
  if (entries.length > 0) return false;
  try {
    if (typeof fsModule.rmdirSync === "function") {
      fsModule.rmdirSync(resolvedRoot);
    } else {
      fsModule.rmSync(resolvedRoot, { recursive: true, force: true });
    }
    return true;
  } catch {
    return false;
  }
}

function removePath(target) {
  if (!target || !fs.existsSync(target)) return false;
  try {
    fs.rmSync(target, { recursive: true, force: true });
    return true;
  } catch {
    return false;
  }
}

function removeBinsInDir(dirPath) {
  if (!dirPath || !fs.existsSync(dirPath)) return false;
  let removed = false;
  for (const name of BIN_NAMES) {
    removed = removePath(path.join(dirPath, name)) || removed;
  }
  return removed;
}

function removeNodeModuleAt(dirPath) {
  if (!dirPath) return false;
  return removePath(path.join(dirPath, PACKAGE_NAME));
}

function removePrefixInstalls(prefix) {
  if (!prefix) return;
  removeBinsInDir(path.join(prefix, "bin"));
  removeBinsInDir(prefix);
  removeNodeModuleAt(path.join(prefix, "lib", "node_modules"));
  removeNodeModuleAt(path.join(prefix, "node_modules"));
}

function removeHomebrewInstalls() {
  const prefixes = new Set();
  if (process.env.HOMEBREW_PREFIX) prefixes.add(process.env.HOMEBREW_PREFIX);
  prefixes.add("/opt/homebrew");
  prefixes.add("/usr/local");
  for (const prefix of prefixes) {
    removeBinsInDir(path.join(prefix, "bin"));
  }
}

function removeNvmInstalls() {
  const home = os.homedir();
  const roots = new Set();
  if (process.env.NVM_DIR) roots.add(process.env.NVM_DIR);
  if (process.env.NVM_HOME) roots.add(process.env.NVM_HOME);
  roots.add(path.join(home, ".nvm"));
  if (process.env.NVM_BIN) {
    removeBinsInDir(process.env.NVM_BIN);
  }
  for (const root of roots) {
    if (!root || !fs.existsSync(root)) continue;
    const versionsRoot = path.join(root, "versions", "node");
    if (!fs.existsSync(versionsRoot)) continue;
    const entries = fs.readdirSync(versionsRoot, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const versionDir = path.join(versionsRoot, entry.name);
      removeBinsInDir(path.join(versionDir, "bin"));
      removeNodeModuleAt(path.join(versionDir, "lib", "node_modules"));
      removeNodeModuleAt(path.join(versionDir, "node_modules"));
    }
  }
}

function removeCargoInstalls() {
  const home = os.homedir();
  removeBinsInDir(path.join(home, ".cargo", "bin"));
}

function purgeExternalInstalls() {
  const prefix = process.env.npm_config_prefix || process.env.PREFIX;
  if (prefix) removePrefixInstalls(prefix);
  removeHomebrewInstalls();
  removeNvmInstalls();
  removeCargoInstalls();
}

async function main() {
  unregisterStartup();
  stopDaemonFromLock();
  stopDaemonByName();
  const freed = await waitForPortFree();
  const running = findRunningDaemonFromLocks();
  if (!freed || running) {
    console.warn(
      `[docdex] ${DEFAULT_HOST}:${DEFAULT_DAEMON_PORT} is still in use or a daemon PID is alive; stop the process manually before reinstalling.`
    );
    for (const line of manualStopInstructions()) {
      console.warn(`[docdex] ${line}`);
    }
  }
  removeClientConfigs();
  clearStartupFailure();
  removeDaemonRootNotice();
  removeDocdexRootIfEmpty();
  purgeExternalInstalls();
}

if (require.main === module) {
  main().catch(() => process.exit(0));
}

module.exports = {
  removeMcpServerJson,
  removeCodexConfig,
  removeMcpServerYaml,
  stopDaemonFromLock,
  stopDaemonByName,
  unregisterStartup,
  removeClientConfigs,
  removeDocdexRootIfEmpty
};
