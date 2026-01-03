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
  const override = process.env.DOCDEX_DAEMON_LOCK_PATH;
  if (override && override.trim()) return override.trim();
  return path.join(os.homedir(), ".docdex", "daemon.lock");
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
          path.join(userProfile, ".cursor", "mcp.json"),
          path.join(userProfile, ".cursor", "settings.json"),
          path.join(userProfile, ".codeium", "windsurf", "mcp_config.json"),
          path.join(appData, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
          path.join(appData, "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json"),
          path.join(userProfile, ".continue", "config.json"),
          path.join(userProfile, ".kiro", "settings", "mcp.json"),
          path.join(appData, "Zed", "settings.json")
        ],
        toml: [path.join(userProfile, ".codex", "config.toml")],
        yaml: [path.join(appData, "Aider", "config.yml")]
      };
    case "darwin":
      return {
        json: [
          path.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
          path.join(home, ".cursor", "mcp.json"),
          path.join(home, ".cursor", "settings.json"),
          path.join(home, ".codeium", "windsurf", "mcp_config.json"),
          path.join(home, "Library", "Application Support", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
          path.join(home, "Library", "Application Support", "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json"),
          path.join(home, ".continue", "config.json"),
          path.join(home, ".kiro", "settings", "mcp.json"),
          path.join(home, ".config", "zed", "settings.json")
        ],
        toml: [path.join(home, ".codex", "config.toml")],
        yaml: [path.join(home, ".config", "aider", "config.yml"), path.join(home, ".aider.conf.yml")]
      };
    default:
      return {
        json: [
          path.join(home, ".config", "Claude", "claude_desktop_config.json"),
          path.join(home, ".cursor", "mcp.json"),
          path.join(home, ".cursor", "settings.json"),
          path.join(home, ".codeium", "windsurf", "mcp_config.json"),
          path.join(home, ".config", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
          path.join(home, ".config", "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json"),
          path.join(home, ".continue", "config.json"),
          path.join(home, ".kiro", "settings", "mcp.json"),
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
    if (!section || typeof section !== "object" || Array.isArray(section)) continue;
    if (!Object.prototype.hasOwnProperty.call(section, name)) continue;
    delete section[name];
    changed = true;
    if (Object.keys(section).length === 0) delete root[key];
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

function stopDaemonByName() {
  if (process.platform === "win32") {
    spawnSync("taskkill", ["/IM", "docdexd.exe", "/T", "/F"]);
    return true;
  }
  spawnSync("pkill", ["-TERM", "-x", "docdexd"]);
  spawnSync("pkill", ["-TERM", "-f", "docdexd daemon"]);
  return true;
}

function stopMcpByName() {
  if (process.platform === "win32") {
    spawnSync("taskkill", ["/IM", "docdex-mcp-server.exe", "/T", "/F"]);
    return true;
  }
  spawnSync("pkill", ["-TERM", "-x", "docdex-mcp-server"]);
  spawnSync("pkill", ["-TERM", "-f", "docdex-mcp-server"]);
  return true;
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

async function main() {
  const stopped = stopDaemonFromLock();
  if (!stopped) {
    stopDaemonByName();
  }
  stopMcpByName();
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
  removeMcpServerYaml,
  stopDaemonFromLock,
  stopDaemonByName,
  unregisterStartup,
  removeClientConfigs
};
