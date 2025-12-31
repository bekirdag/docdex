#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");

const { detectPlatformKey, UnsupportedPlatformError } = require("./platform");

const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_PORT_PRIMARY = 3000;
const DEFAULT_PORT_FALLBACK = 3210;
const STARTUP_FAILURE_MARKER = "startup_registration_failed.json";

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
  return { port, url, configPath };
}

module.exports = {
  runPostInstallSetup,
  upsertServerConfig,
  parseServerBind,
  upsertMcpServerJson,
  upsertCodexConfig,
  pickAvailablePort,
  configUrlForPort
};
