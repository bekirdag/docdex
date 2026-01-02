#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const DAEMON_TASK_NAME = "Docdex Daemon";
const STARTUP_FAILURE_MARKER = "startup_registration_failed.json";

function daemonRootPath() {
  return path.join(os.homedir(), ".docdex", "daemon_root");
}

function stateDir() {
  return path.join(os.homedir(), ".docdex", "state");
}

function daemonLockPath() {
  return path.join(os.homedir(), ".docdex", "daemon.lock");
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
  if (!root.mcpServers || typeof root.mcpServers !== "object" || Array.isArray(root.mcpServers)) {
    return false;
  }
  if (!Object.prototype.hasOwnProperty.call(root.mcpServers, name)) return false;
  delete root.mcpServers[name];
  if (Object.keys(root.mcpServers).length === 0) delete root.mcpServers;
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

  contents = removeArrayBlocks(contents);
  contents = removeNestedSection(contents);
  contents = removeTableEntry(contents);

  if (contents !== original) {
    fs.writeFileSync(pathname, contents.endsWith("\n") ? contents : `${contents}\n`);
    return true;
  }
  return false;
}

function killPid(pid) {
  if (!pid) return false;
  try {
    if (process.platform === "win32") {
      spawnSync("taskkill", ["/PID", String(pid), "/T", "/F"]);
      return true;
    }
    process.kill(pid, "SIGTERM");
    return true;
  } catch {
    return false;
  }
}

function stopDaemonFromLock() {
  const lockPath = daemonLockPath();
  if (!fs.existsSync(lockPath)) return false;
  try {
    const raw = fs.readFileSync(lockPath, "utf8");
    const payload = JSON.parse(raw);
    const pid = payload && typeof payload.pid === "number" ? payload.pid : null;
    const stopped = killPid(pid);
    fs.unlinkSync(lockPath);
    return stopped;
  } catch {
    return false;
  }
}

function unregisterStartup() {
  if (process.platform === "darwin") {
    const plistPath = path.join(os.homedir(), "Library", "LaunchAgents", "com.docdex.daemon.plist");
    if (fs.existsSync(plistPath)) {
      const uid = typeof process.getuid === "function" ? process.getuid() : null;
      if (uid != null) {
        spawnSync("launchctl", ["bootout", `gui/${uid}`, plistPath]);
      }
      spawnSync("launchctl", ["unload", "-w", plistPath]);
      spawnSync("launchctl", ["remove", "com.docdex.daemon"]);
      try {
        fs.unlinkSync(plistPath);
      } catch {}
    }
    return true;
  }

  if (process.platform === "linux") {
    const systemdDir = path.join(os.homedir(), ".config", "systemd", "user");
    const unitPath = path.join(systemdDir, "docdexd.service");
    spawnSync("systemctl", ["--user", "disable", "--now", "docdexd.service"]);
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
  const readme = path.join(root, "README.txt");
  if (fs.existsSync(readme)) {
    try {
      fs.unlinkSync(readme);
    } catch {}
  }
}

function removeClientConfigs() {
  const paths = clientConfigPaths();
  removeMcpServerJson(paths.claude);
  removeMcpServerJson(paths.cursor);
  removeCodexConfig(paths.codex);
}

async function main() {
  stopDaemonFromLock();
  unregisterStartup();
  removeClientConfigs();
  clearStartupFailure();
  removeDaemonRootNotice();
}

if (require.main === module) {
  main().catch(() => process.exit(0));
}

module.exports = {
  removeMcpServerJson,
  removeCodexConfig,
  stopDaemonFromLock,
  unregisterStartup,
  removeClientConfigs
};
