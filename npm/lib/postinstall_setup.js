#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const net = require("node:net");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const readline = require("node:readline");
const tty = require("node:tty");
const { spawn, spawnSync } = require("node:child_process");

const { detectPlatformKey, UnsupportedPlatformError } = require("./platform");
const {
  resolveDistBaseDir,
  resolveDistBaseCandidates,
  resolveBinDir,
  resolveWindowsRunnerPath,
  resolveWindowsSetupRunnerPath
} = require("./paths");

const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_DAEMON_PORT = 28491;
const DAEMON_HEALTH_TIMEOUT_MS = 8000;
const DAEMON_HEALTH_REQUEST_TIMEOUT_MS = 1000;
const DAEMON_HEALTH_POLL_INTERVAL_MS = 200;
const DAEMON_HEALTH_PATH = "/healthz";
const DAEMON_INFO_PATH = "/ai-help";
const DAEMON_PORT_RELEASE_TIMEOUT_MS = 5000;
const STARTUP_FAILURE_MARKER = "startup_registration_failed.json";
const DEFAULT_OLLAMA_MODEL = "nomic-embed-text";
const DEFAULT_OLLAMA_CHAT_MODEL = "phi3.5:3.8b";
const DEFAULT_OLLAMA_CHAT_MODEL_SIZE_GIB = 2.2;
const SETUP_PENDING_MARKER = "setup_pending.json";
const AGENTS_DOC_FILENAME = "agents.md";
const DOCDEX_INFO_START_PREFIX = "---- START OF DOCDEX INFO V";
const DOCDEX_INFO_END = "---- END OF DOCDEX INFO -----";
const DOCDEX_INFO_END_LEGACY = "---- END OF DOCDEX INFO ----";

function defaultConfigPath() {
  return path.join(os.homedir(), ".docdex", "config.toml");
}

function daemonRootPath() {
  return path.join(os.homedir(), ".docdex", "daemon_root");
}

function stateDir() {
  return path.join(os.homedir(), ".docdex", "state");
}

function setupPendingPath() {
  return path.join(stateDir(), SETUP_PENDING_MARKER);
}

function daemonLockPaths() {
  const root = path.join(os.homedir(), ".docdex");
  const paths = [];
  if (process.env.DOCDEX_DAEMON_LOCK_PATH) {
    paths.push(process.env.DOCDEX_DAEMON_LOCK_PATH);
  }
  paths.push(path.join(root, "locks", "daemon.lock"));
  paths.push(path.join(root, "daemon.lock"));
  return Array.from(new Set(paths.filter(Boolean)));
}

function configUrlForPort(port) {
  return `http://localhost:${port}/sse`;
}

function configStreamableUrlForPort(port) {
  return `http://localhost:${port}/v1/mcp`;
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

function checkDaemonHealth({ host, port, timeoutMs = DAEMON_HEALTH_REQUEST_TIMEOUT_MS }) {
  return new Promise((resolve) => {
    const req = http.request(
      {
        host,
        port,
        path: DAEMON_HEALTH_PATH,
        method: "GET",
        timeout: timeoutMs
      },
      (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => {
          body += chunk;
        });
        res.on("end", () => {
          resolve(res.statusCode === 200 && body.trim() === "ok");
        });
      }
    );
    req.on("timeout", () => {
      req.destroy();
      resolve(false);
    });
    req.on("error", () => resolve(false));
    req.end();
  });
}

async function waitForDaemonHealthy({ host, port, timeoutMs = DAEMON_HEALTH_TIMEOUT_MS }) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await checkDaemonHealth({ host, port })) {
      return true;
    }
    await sleep(DAEMON_HEALTH_POLL_INTERVAL_MS);
  }
  return false;
}

async function waitForPortAvailable({
  host,
  port,
  timeoutMs = DAEMON_PORT_RELEASE_TIMEOUT_MS
}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await isPortAvailable(port, host)) {
      return true;
    }
    await sleep(DAEMON_HEALTH_POLL_INTERVAL_MS);
  }
  return false;
}

function isPidRunning(pid) {
  if (!Number.isFinite(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err?.code === "EPERM";
  }
}

function readDaemonLockMetadataForPort(port) {
  for (const lockPath of daemonLockPaths()) {
    if (!lockPath || !fs.existsSync(lockPath)) continue;
    try {
      const raw = fs.readFileSync(lockPath, "utf8");
      if (!raw.trim()) continue;
      const payload = JSON.parse(raw);
      const lockPort = Number(payload?.port);
      const pid = Number(payload?.pid);
      if (!Number.isFinite(lockPort) || lockPort !== port) continue;
      return { pid, port: lockPort };
    } catch {
      continue;
    }
  }
  return null;
}

function normalizeVersion(value) {
  return String(value || "")
    .trim()
    .replace(/^v/i, "");
}

function fetchDaemonInfo({ host, port, timeoutMs = DAEMON_HEALTH_REQUEST_TIMEOUT_MS }) {
  return new Promise((resolve) => {
    const req = http.request(
      {
        host,
        port,
        path: DAEMON_INFO_PATH,
        method: "GET",
        timeout: timeoutMs
      },
      (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => {
          body += chunk;
        });
        res.on("end", () => {
          if (res.statusCode !== 200) return resolve(null);
          try {
            const payload = JSON.parse(body);
            resolve(payload);
          } catch {
            resolve(null);
          }
        });
      }
    );
    req.on("timeout", () => {
      req.destroy();
      resolve(null);
    });
    req.on("error", () => resolve(null));
    req.end();
  });
}

function checkDocdexIdentity({ host, port, timeoutMs = DAEMON_HEALTH_REQUEST_TIMEOUT_MS }) {
  return fetchDaemonInfo({ host, port, timeoutMs }).then((payload) => payload?.product === "Docdex");
}

async function resolveDaemonPortState({ host, port, logger, deps } = {}) {
  const log = logger || console;
  const helpers = {
    isPortAvailable,
    checkDaemonHealth,
    checkDocdexIdentity,
    stopDaemonService,
    stopDaemonFromLock,
    stopDaemonByName,
    clearDaemonLocks,
    sleep,
    readDaemonLockMetadataForPort,
    isPidRunning,
    normalizeVersion
  };
  if (deps && typeof deps === "object") {
    Object.assign(helpers, deps);
  }

  let available = await helpers.isPortAvailable(port, host);
  if (available) return { available: true, reuseExisting: false, stopped: false };

  helpers.stopDaemonService({ logger: log });
  helpers.stopDaemonFromLock({ logger: log });
  helpers.stopDaemonByName({ logger: log });
  await helpers.sleep(DAEMON_HEALTH_POLL_INTERVAL_MS);

  available = await helpers.isPortAvailable(port, host);
  if (available) {
    helpers.clearDaemonLocks();
    return { available: true, reuseExisting: false, stopped: true };
  }

  const lockMeta = helpers.readDaemonLockMetadataForPort(port);
  const lockRunning = lockMeta ? helpers.isPidRunning(lockMeta.pid) : false;
  const healthy = await helpers.checkDaemonHealth({ host, port });
  const identity = lockRunning ? true : await helpers.checkDocdexIdentity({ host, port });
  const reuseExisting = Boolean(lockRunning || healthy || identity);
  if (reuseExisting) {
    log.warn?.(`[docdex] ${host}:${port} already in use by a running docdex daemon; reusing it.`);
  }
  return { available: false, reuseExisting, stopped: false };
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

function stopDaemonService({ logger } = {}) {
  if (process.platform === "darwin") {
    const uid = typeof process.getuid === "function" ? process.getuid() : null;
    const domain = uid != null ? `gui/${uid}` : null;
    const plistPath = path.join(os.homedir(), "Library", "LaunchAgents", "com.docdex.daemon.plist");
    const bootoutByLabel = domain
      ? spawnSync("launchctl", ["bootout", domain, "com.docdex.daemon"])
      : spawnSync("launchctl", ["bootout", "com.docdex.daemon"]);
    const bootoutByPath = domain
      ? spawnSync("launchctl", ["bootout", domain, plistPath])
      : spawnSync("launchctl", ["bootout", plistPath]);
    const fallback = spawnSync("launchctl", ["unload", "-w", plistPath]);
    spawnSync("launchctl", ["remove", "com.docdex.daemon"]);
    if (bootoutByLabel.status === 0 || bootoutByPath.status === 0 || fallback.status === 0) {
      return true;
    }
    logger?.warn?.(
      `[docdex] launchctl stop failed: ${bootoutByLabel.stderr || bootoutByPath.stderr || fallback.stderr || "unknown error"}`
    );
    return false;
  }
  if (process.platform === "linux") {
    const stop = spawnSync("systemctl", ["--user", "stop", "docdexd.service"]);
    if (stop.status === 0) return true;
    logger?.warn?.(`[docdex] systemd stop failed: ${stop.stderr || "unknown error"}`);
    return false;
  }
  if (process.platform === "win32") {
    const stop = spawnSync("schtasks", ["/End", "/TN", "Docdex Daemon"]);
    if (stop.status === 0) return true;
    logger?.warn?.(`[docdex] schtasks stop failed: ${stop.stderr || "unknown error"}`);
    return false;
  }
  return false;
}

function removeDaemonService({ logger, distBaseDir, env } = {}) {
  if (process.platform === "darwin") {
    const uid = typeof process.getuid === "function" ? process.getuid() : null;
    const domain = uid != null ? `gui/${uid}` : null;
    const plistPath = path.join(os.homedir(), "Library", "LaunchAgents", "com.docdex.daemon.plist");
    const systemPlistPath = "/Library/LaunchDaemons/com.docdex.daemon.plist";
    if (domain) {
      spawnSync("launchctl", ["bootout", domain, "com.docdex.daemon"]);
      spawnSync("launchctl", ["bootout", domain, plistPath]);
    } else {
      spawnSync("launchctl", ["bootout", "com.docdex.daemon"]);
      spawnSync("launchctl", ["bootout", plistPath]);
    }
    spawnSync("launchctl", ["remove", "com.docdex.daemon"]);
    spawnSync("launchctl", ["unload", "-w", plistPath]);
    if (fs.existsSync(plistPath)) {
      try {
        fs.unlinkSync(plistPath);
      } catch (err) {
        logger?.warn?.(`[docdex] failed to remove LaunchAgent plist: ${err?.message || err}`);
      }
    }
    if (fs.existsSync(systemPlistPath)) {
      spawnSync("launchctl", ["bootout", "system", systemPlistPath]);
      spawnSync("launchctl", ["remove", "com.docdex.daemon"]);
      try {
        fs.unlinkSync(systemPlistPath);
      } catch (err) {
        logger?.warn?.(`[docdex] failed to remove LaunchDaemon plist: ${err?.message || err}`);
      }
    }
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
      } catch (err) {
        logger?.warn?.(`[docdex] failed to remove systemd unit: ${err?.message || err}`);
      }
      spawnSync("systemctl", ["--user", "daemon-reload"]);
    }
    return true;
  }
  if (process.platform === "win32") {
    const taskName = "Docdex Daemon";
    spawnSync("schtasks", ["/End", "/TN", taskName]);
    spawnSync("schtasks", ["/Delete", "/TN", taskName, "/F"]);
    const resolvedDistBaseDir = distBaseDir || resolveDistBaseDir({ env, fsModule: fs });
    const runnerPath = resolveWindowsRunnerPath({ distBaseDir: resolvedDistBaseDir, pathModule: path });
    if (runnerPath && fs.existsSync(runnerPath)) {
      try {
        fs.unlinkSync(runnerPath);
      } catch (err) {
        logger?.warn?.(`[docdex] failed to remove Windows runner: ${err?.message || err}`);
      }
    }
    return true;
  }
  return false;
}

function startDaemonService({ logger } = {}) {
  if (process.platform === "darwin") {
    const uid = typeof process.getuid === "function" ? process.getuid() : null;
    const domain = uid != null ? `gui/${uid}` : null;
    const kickstart = domain
      ? spawnSync("launchctl", ["kickstart", "-k", `${domain}/com.docdex.daemon`])
      : spawnSync("launchctl", ["kickstart", "-k", "com.docdex.daemon"]);
    if (kickstart.status === 0) return true;
    const start = spawnSync("launchctl", ["start", "com.docdex.daemon"]);
    if (start.status === 0) return true;
    logger?.warn?.(`[docdex] launchctl start failed: ${kickstart.stderr || start.stderr || "unknown error"}`);
    return false;
  }
  if (process.platform === "linux") {
    const start = spawnSync("systemctl", ["--user", "restart", "docdexd.service"]);
    if (start.status === 0) return true;
    logger?.warn?.(`[docdex] systemd start failed: ${start.stderr || "unknown error"}`);
    return false;
  }
  if (process.platform === "win32") {
    const run = spawnSync("schtasks", ["/Run", "/TN", "Docdex Daemon"]);
    if (run.status === 0) return true;
    logger?.warn?.(`[docdex] schtasks run failed: ${run.stderr || "unknown error"}`);
    return false;
  }
  return false;
}

function stopDaemonByName({ logger } = {}) {
  if (process.platform === "win32") {
    const result = spawnSync("taskkill", ["/IM", "docdexd.exe", "/T", "/F"]);
    if (result?.error?.code === "ENOENT") return false;
    return true;
  }
  const result = spawnSync("pkill", ["-TERM", "-x", "docdexd"]);
  if (result?.error?.code === "ENOENT") {
    spawnSync("killall", ["-TERM", "docdexd"]);
    return false;
  }
  spawnSync("pkill", ["-TERM", "-f", "docdexd"]);
  return true;
}

async function cleanupExistingDaemon({ logger, env, distBaseDir, host, port } = {}) {
  const log = logger || console;
  stopDaemonService({ logger: log });
  stopDaemonFromLock({ logger: log });
  stopDaemonByName({ logger: log });
  removeDaemonService({ logger: log, distBaseDir, env });
  clearDaemonLocks();
  if (!host || !port) return true;
  const released = await waitForPortAvailable({ host, port });
  if (!released) {
    log.warn?.(`[docdex] ${host}:${port} still in use after daemon cleanup.`);
  }
  return released;
}

function clearDaemonLocks() {
  let removed = false;
  for (const lockPath of daemonLockPaths()) {
    if (!lockPath || !fs.existsSync(lockPath)) continue;
    try {
      const resolved = path.resolve(lockPath);
      const home = path.resolve(os.homedir());
      if (!resolved.startsWith(home + path.sep)) continue;
      fs.unlinkSync(lockPath);
      removed = true;
    } catch {
      continue;
    }
  }
  return removed;
}

function stopDaemonFromLock({ logger } = {}) {
  let stopped = false;
  for (const lockPath of daemonLockPaths()) {
    if (!lockPath || !fs.existsSync(lockPath)) continue;
    try {
      const raw = fs.readFileSync(lockPath, "utf8");
      if (!raw.trim()) continue;
      const payload = JSON.parse(raw);
      const pid = Number(payload?.pid);
      if (!Number.isFinite(pid) || pid <= 0) continue;
      try {
        process.kill(pid, "SIGTERM");
        stopped = true;
      } catch (err) {
        logger?.warn?.(`[docdex] failed to stop daemon pid ${pid}: ${err?.message || err}`);
      }
    } catch {
      continue;
    }
  }
  return stopped;
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

function agentsDocSourcePath() {
  return path.join(__dirname, "..", "assets", AGENTS_DOC_FILENAME);
}

function resolvePackageVersion() {
  const packagePath = path.join(__dirname, "..", "package.json");
  if (!fs.existsSync(packagePath)) return "unknown";
  try {
    const raw = fs.readFileSync(packagePath, "utf8");
    const parsed = JSON.parse(raw);
    return typeof parsed.version === "string" && parsed.version.trim() ? parsed.version.trim() : "unknown";
  } catch {
    return "unknown";
  }
}

function loadAgentInstructions() {
  const sourcePath = agentsDocSourcePath();
  if (!fs.existsSync(sourcePath)) return "";
  try {
    return fs.readFileSync(sourcePath, "utf8");
  } catch {
    return "";
  }
}

function normalizeInstructionText(value) {
  return String(value || "").trim();
}

function docdexBlockStart(version) {
  return `${DOCDEX_INFO_START_PREFIX}${version} ----`;
}

function docdexInfoEndPattern() {
  return `(?:${escapeRegExp(DOCDEX_INFO_END)}|${escapeRegExp(DOCDEX_INFO_END_LEGACY)})`;
}

function buildDocdexInstructionBlock(instructions) {
  const next = normalizeInstructionText(instructions);
  if (!next) return "";
  if (hasDocdexBlock(next)) return next;
  const version = resolvePackageVersion();
  return `${docdexBlockStart(version)}\n${next}\n${DOCDEX_INFO_END}`;
}

function extractDocdexBlockBody(text) {
  const match = String(text || "").match(
    new RegExp(
      `${escapeRegExp(DOCDEX_INFO_START_PREFIX)}[^\\r\\n]* ----\\r?\\n([\\s\\S]*?)\\r?\\n${docdexInfoEndPattern()}`
    )
  );
  return match ? normalizeInstructionText(match[1]) : "";
}

function extractDocdexBlockVersion(text) {
  const match = String(text || "").match(
    new RegExp(`${escapeRegExp(DOCDEX_INFO_START_PREFIX)}([^\\s]+) ----`)
  );
  return match ? match[1] : null;
}

function hasDocdexBlockVersion(text, version) {
  if (!version) return false;
  return String(text || "").includes(docdexBlockStart(version));
}

function hasDocdexBlock(text) {
  const source = String(text || "");
  return (
    source.includes(DOCDEX_INFO_START_PREFIX) &&
    (source.includes(DOCDEX_INFO_END) || source.includes(DOCDEX_INFO_END_LEGACY))
  );
}

function stripDocdexBlocks(text) {
  const re = new RegExp(
    `${escapeRegExp(DOCDEX_INFO_START_PREFIX)}[^\\r\\n]* ----\\r?\\n[\\s\\S]*?\\r?\\n${docdexInfoEndPattern()}\\r?\\n?`,
    "g"
  );
  return String(text || "").replace(re, "").trim();
}

function stripDocdexBlocksExcept(text, version) {
  if (!version) return stripDocdexBlocks(text);
  const source = String(text || "");
  const re = new RegExp(
    `${escapeRegExp(DOCDEX_INFO_START_PREFIX)}[^\\r\\n]* ----\\r?\\n[\\s\\S]*?\\r?\\n${docdexInfoEndPattern()}\\r?\\n?`,
    "g"
  );
  let result = "";
  let lastIndex = 0;
  let match;
  while ((match = re.exec(source))) {
    const before = source.slice(lastIndex, match.index);
    result += before;
    const block = match[0];
    const blockVersion = extractDocdexBlockVersion(block);
    if (blockVersion === version) {
      result += block;
    }
    lastIndex = match.index + block.length;
  }
  result += source.slice(lastIndex);
  return result;
}

function stripLegacyDocdexBodySegment(segment, body) {
  if (!body) return String(segment || "");
  const normalizedSegment = String(segment || "").replace(/\r\n/g, "\n");
  const normalizedBody = String(body || "").replace(/\r\n/g, "\n");
  if (!normalizedBody.trim()) return normalizedSegment;
  const re = new RegExp(`\\n?${escapeRegExp(normalizedBody)}\\n?`, "g");
  return normalizedSegment.replace(re, "\n").replace(/\n{3,}/g, "\n\n");
}

function stripLegacyDocdexBody(text, body) {
  if (!body) return String(text || "");
  const source = String(text || "").replace(/\r\n/g, "\n");
  const re = new RegExp(
    `${escapeRegExp(DOCDEX_INFO_START_PREFIX)}[^\\n]* ----\\n[\\s\\S]*?\\n${docdexInfoEndPattern()}\\n?`,
    "g"
  );
  let result = "";
  let lastIndex = 0;
  let match;
  while ((match = re.exec(source))) {
    const before = source.slice(lastIndex, match.index);
    result += stripLegacyDocdexBodySegment(before, body);
    result += match[0];
    lastIndex = match.index + match[0].length;
  }
  result += stripLegacyDocdexBodySegment(source.slice(lastIndex), body);
  return result;
}

function mergeInstructionText(existing, instructions, { prepend = false } = {}) {
  const next = normalizeInstructionText(instructions);
  if (!next) return normalizeInstructionText(existing);
  const existingText = String(existing || "");
  const current = normalizeInstructionText(existingText);
  if (!current) return next;
  const version = extractDocdexBlockVersion(next);
  if (version) {
    const body = extractDocdexBlockBody(next);
    const cleaned = stripLegacyDocdexBody(existingText, body);
    const withoutOldBlocks = stripDocdexBlocksExcept(cleaned, version);
    if (hasDocdexBlockVersion(withoutOldBlocks, version)) return withoutOldBlocks;
    const remainder = normalizeInstructionText(stripDocdexBlocks(withoutOldBlocks));
    if (!remainder) return next;
    return prepend ? `${next}\n\n${remainder}` : `${remainder}\n\n${next}`;
  }
  if (existingText.includes(next)) return existingText;
  return prepend ? `${next}\n\n${current}` : `${current}\n\n${next}`;
}

function writeTextFile(pathname, contents) {
  const next = contents.endsWith("\n") ? contents : `${contents}\n`;
  let current = "";
  if (fs.existsSync(pathname)) {
    current = fs.readFileSync(pathname, "utf8");
    if (current === next) return false;
  }
  fs.mkdirSync(path.dirname(pathname), { recursive: true });
  fs.writeFileSync(pathname, next);
  return true;
}

function upsertPromptFile(pathname, instructions, { prepend = false } = {}) {
  const next = normalizeInstructionText(instructions);
  if (!next) return false;
  let current = "";
  if (fs.existsSync(pathname)) {
    current = fs.readFileSync(pathname, "utf8");
  }
  const merged = mergeInstructionText(current, instructions, { prepend });
  if (!merged) return false;
  if (merged === current) return false;
  return writeTextFile(pathname, merged);
}

function removePromptFile(pathname) {
  if (!fs.existsSync(pathname)) return false;
  const current = fs.readFileSync(pathname, "utf8");
  const stripped = stripDocdexBlocks(current);
  if (normalizeInstructionText(stripped) === normalizeInstructionText(current)) return false;
  if (!stripped) {
    fs.unlinkSync(pathname);
    return true;
  }
  return writeTextFile(pathname, stripped);
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function upsertYamlInstruction(pathname, key, instructions) {
  const next = normalizeInstructionText(instructions);
  if (!next) return false;
  let current = "";
  if (fs.existsSync(pathname)) {
    current = fs.readFileSync(pathname, "utf8");
  }
  const lines = current.split(/\r?\n/);
  const blockRe = new RegExp(`^(\\s*)${escapeRegExp(key)}\\s*:\\s*(\\|[+-]?)?\\s*$`);
  for (let idx = 0; idx < lines.length; idx += 1) {
    const match = lines[idx].match(blockRe);
    if (!match) continue;
    const indent = match[1] || "";
    const blockIndent = `${indent}  `;
    let existingBlock = "";
    let blockEnd = idx + 1;
    if (match[2]) {
      for (let j = idx + 1; j < lines.length; j += 1) {
        const line = lines[j];
        if (!line.trim()) {
          blockEnd = j + 1;
          continue;
        }
        const leading = line.match(/^\s*/)[0].length;
        if (leading <= indent.length) break;
        blockEnd = j + 1;
      }
      const blockLines = lines.slice(idx + 1, blockEnd);
      existingBlock = blockLines
        .map((line) => {
          if (!line.trim()) return "";
          return line.startsWith(blockIndent) ? line.slice(blockIndent.length) : line.trimStart();
        })
        .join("\n");
    } else {
      const inlineMatch = lines[idx].match(new RegExp(`^(\\s*)${escapeRegExp(key)}\\s*:\\s*(.*)$`));
      existingBlock = inlineMatch ? inlineMatch[2].trim() : "";
    }
    const merged = mergeInstructionText(existingBlock, instructions);
    if (!merged) return false;
    if (normalizeInstructionText(merged) === normalizeInstructionText(existingBlock) && match[2]) return false;
    const mergedLines = merged.split(/\r?\n/).map((line) => `${blockIndent}${line}`);
    const updatedLines = [
      ...lines.slice(0, idx),
      `${indent}${key}: |`,
      ...mergedLines,
      ...lines.slice(match[2] ? blockEnd : idx + 1)
    ];
    return writeTextFile(pathname, updatedLines.join("\n").trimEnd());
  }
  const contentLines = next.split(/\r?\n/).map((line) => `  ${line}`);
  const block = `${key}: |\n${contentLines.join("\n")}`;
  const merged = current.trim() ? `${current.trim()}\n\n${block}` : block;
  return writeTextFile(pathname, merged);
}

function upsertClaudeInstructions(pathname, instructions) {
  return upsertPromptFile(pathname, instructions);
}

function upsertContinueJsonInstructions(pathname, instructions) {
  const { value } = readJson(pathname);
  if (typeof value !== "object" || value == null || Array.isArray(value)) return false;
  const merged = mergeInstructionText(value.systemMessage, instructions);
  if (!merged || merged === value.systemMessage) return false;
  value.systemMessage = merged;
  writeJson(pathname, value);
  return true;
}

function countLeadingWhitespace(line) {
  const match = line.match(/^\s*/);
  return match ? match[0].length : 0;
}

function isYamlTopLevelKey(line, baseIndent) {
  const indent = countLeadingWhitespace(line);
  if (indent > baseIndent) return false;
  const trimmed = line.trimStart();
  if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("-")) return false;
  return trimmed.includes(":");
}

function hasYamlContent(lines) {
  return lines.some((line) => {
    const trimmed = line.trim();
    return trimmed && !trimmed.startsWith("#");
  });
}

function splitInlineYamlList(value) {
  const trimmed = String(value || "").trim();
  if (trimmed === "[]") return [];
  if (!trimmed.startsWith("[") || !trimmed.endsWith("]")) return null;
  const inner = trimmed.slice(1, -1);
  const items = [];
  let current = "";
  let inSingle = false;
  let inDouble = false;
  let escaped = false;
  for (const ch of inner) {
    if (escaped) {
      current += ch;
      escaped = false;
      continue;
    }
    if (ch === "\\\\") {
      escaped = true;
      current += ch;
      continue;
    }
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
      current += ch;
      continue;
    }
    if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
      current += ch;
      continue;
    }
    if (ch === "," && !inSingle && !inDouble) {
      const next = current.trim();
      if (next) items.push(next);
      current = "";
      continue;
    }
    current += ch;
  }
  const next = current.trim();
  if (next) items.push(next);
  return items;
}

function inlineRulesToItems(value, itemIndent) {
  const trimmed = String(value || "").trim();
  if (!trimmed) return [];
  const prefix = " ".repeat(itemIndent);
  const split = splitInlineYamlList(trimmed);
  if (split) {
    return split.map((item) => [`${prefix}- ${item}`]).filter((item) => item[0].trim() !== `${prefix}-`);
  }
  return [[`${prefix}- ${trimmed}`]];
}

function buildYamlRuleBlock(itemIndent, instructions) {
  const prefix = " ".repeat(itemIndent);
  const contentPrefix = " ".repeat(itemIndent + 2);
  const lines = [`${prefix}- |`];
  for (const line of String(instructions).split(/\r?\n/)) {
    lines.push(`${contentPrefix}${line}`);
  }
  return lines;
}

function rewriteContinueYamlRules(source, instructions, addDocdex) {
  const lines = String(source || "").split(/\r?\n/);
  const ruleLineRe = /^(\s*)rules\s*:(.*)$/;
  let rulesIndex = -1;
  let rulesIndent = 0;
  let rulesInline = "";
  for (let i = 0; i < lines.length; i += 1) {
    const match = lines[i].match(ruleLineRe);
    if (!match) continue;
    rulesIndex = i;
    rulesIndent = match[1]?.length || 0;
    rulesInline = (match[2] || "").trim();
    if (rulesInline.includes("#")) {
      rulesInline = rulesInline.split("#")[0].trim();
    }
    if (rulesInline.startsWith("#")) rulesInline = "";
    break;
  }

  if (rulesIndex === -1) {
    if (!addDocdex) return null;
    const trimmed = String(source || "").trimEnd();
    const docdexBlock = buildYamlRuleBlock(2, instructions);
    const prefix = trimmed ? `${trimmed}\n\n` : "";
    return `${prefix}rules:\n${docdexBlock.join("\n")}`;
  }

  let endIndex = lines.length;
  for (let i = rulesIndex + 1; i < lines.length; i += 1) {
    if (isYamlTopLevelKey(lines[i], rulesIndent)) {
      endIndex = i;
      break;
    }
  }
  const blockLines = lines.slice(rulesIndex + 1, endIndex);
  const preLines = [];
  const items = [];
  let currentItem = [];
  let itemIndent = null;
  let startedItems = false;

  for (const line of blockLines) {
    const trimmed = line.trimStart();
    const indent = countLeadingWhitespace(line);
    const isItem = trimmed.startsWith("-") && indent > rulesIndent;
    if (isItem) {
      if (itemIndent == null) itemIndent = indent;
      if (indent === itemIndent) {
        if (startedItems && currentItem.length) {
          items.push(currentItem);
          currentItem = [];
        }
        startedItems = true;
      }
      currentItem.push(line);
      continue;
    }
    if (startedItems) {
      currentItem.push(line);
    } else {
      preLines.push(line);
    }
  }
  if (currentItem.length) items.push(currentItem);

  const inferredIndent = itemIndent == null ? rulesIndent + 2 : itemIndent;
  if (!items.length && rulesInline) {
    items.push(...inlineRulesToItems(rulesInline, inferredIndent));
    rulesInline = "";
  }

  const keptItems = items.filter((item) => {
    const text = item.join("\n");
    return !hasDocdexBlock(text);
  });

  if (addDocdex) {
    keptItems.push(buildYamlRuleBlock(inferredIndent, instructions));
  }

  const removeRulesBlock =
    !addDocdex && !keptItems.length && !hasYamlContent(preLines) && !rulesInline;

  const output = [];
  output.push(...lines.slice(0, rulesIndex));
  if (!removeRulesBlock) {
    output.push(`${" ".repeat(rulesIndent)}rules:`);
    output.push(...preLines);
    for (const item of keptItems) {
      output.push(...item);
    }
  }
  output.push(...lines.slice(endIndex));
  const next = output.join("\n");
  return next === source ? null : next;
}

function upsertContinueYamlRules(pathname, instructions) {
  if (!fs.existsSync(pathname)) return false;
  const normalized = normalizeInstructionText(instructions);
  if (!normalized) return false;
  const current = fs.readFileSync(pathname, "utf8");
  const updated = rewriteContinueYamlRules(current, normalized, true);
  if (!updated) return false;
  return writeTextFile(pathname, updated);
}

function upsertZedInstructions(pathname, instructions) {
  const { value } = readJson(pathname);
  if (typeof value !== "object" || value == null || Array.isArray(value)) return false;
  if (!value.assistant || typeof value.assistant !== "object" || Array.isArray(value.assistant)) {
    value.assistant = {};
  }
  const merged = mergeInstructionText(value.assistant.system_prompt, instructions);
  if (!merged || merged === value.assistant.system_prompt) return false;
  value.assistant.system_prompt = merged;
  writeJson(pathname, value);
  return true;
}

function upsertVsCodeInstructionKey(value, key, instructions) {
  const existing = typeof value[key] === "string" ? value[key] : "";
  const merged = mergeInstructionText(existing, instructions);
  if (!merged || merged === existing) return false;
  value[key] = merged;
  return true;
}

function removeVsCodeInstructionKey(value, key, instructions, { legacyPath } = {}) {
  if (typeof value[key] !== "string") return false;
  const current = value[key];
  const stripped = stripDocdexBlocks(current);
  if (normalizeInstructionText(stripped) !== normalizeInstructionText(current)) {
    if (!stripped) {
      delete value[key];
    } else {
      value[key] = stripped;
    }
    return true;
  }
  const normalized = normalizeInstructionText(instructions);
  if (current === normalized || (legacyPath && current === legacyPath)) {
    delete value[key];
    return true;
  }
  return false;
}

function upsertVsCodeInstructions(pathname, instructions, legacyPath) {
  const { value } = readJson(pathname);
  if (typeof value !== "object" || value == null || Array.isArray(value)) return false;
  const normalized = normalizeInstructionText(instructions);
  if (!normalized) return false;
  let updated = false;
  if (upsertVsCodeInstructionKey(value, "chat.instructions", instructions)) {
    updated = true;
  }
  if (removeVsCodeInstructionKey(value, "github.copilot.chat.codeGeneration.instructions", instructions)) {
    updated = true;
  }
  if (
    removeVsCodeInstructionKey(value, "copilot.chat.codeGeneration.instructions", instructions, {
      legacyPath
    })
  ) {
    updated = true;
  }
  if (!updated) return false;
  writeJson(pathname, value);
  return true;
}

function upsertMcpServerJson(pathname, url) {
  const { value } = readJson(pathname);
  if (typeof value !== "object" || value == null || Array.isArray(value)) return false;
  const root = value;
  const pickSection = () => {
    if (root.mcpServers && typeof root.mcpServers === "object" && !Array.isArray(root.mcpServers)) {
      return { key: "mcpServers", section: root.mcpServers };
    }
    if (root.mcp_servers && typeof root.mcp_servers === "object" && !Array.isArray(root.mcp_servers)) {
      return { key: "mcp_servers", section: root.mcp_servers };
    }
    return null;
  };
  if (Array.isArray(root.mcpServers)) {
    const idx = root.mcpServers.findIndex((entry) => entry && entry.name === "docdex");
    if (idx >= 0) {
      if (root.mcpServers[idx].url === url) return false;
      root.mcpServers[idx] = { ...root.mcpServers[idx], url };
      writeJson(pathname, root);
      return true;
    }
    root.mcpServers.push({ name: "docdex", url });
    writeJson(pathname, root);
    return true;
  }

  const picked = pickSection();
  if (!picked) {
    root.mcpServers = {};
  }
  const section = picked ? picked.section : root.mcpServers;
  const current = section.docdex;
  if (current && current.url === url) return false;
  section.docdex = { url };
  writeJson(pathname, root);
  return true;
}

function upsertZedConfig(pathname, url) {
  const { value } = readJson(pathname);
  if (typeof value !== "object" || value == null || Array.isArray(value)) return false;
  const root = value;
  if (!root.experimental_mcp_servers || typeof root.experimental_mcp_servers !== "object" || Array.isArray(root.experimental_mcp_servers)) {
    root.experimental_mcp_servers = {};
  }
  const current = root.experimental_mcp_servers.docdex;
  if (current && current.url === url) return false;
  root.experimental_mcp_servers.docdex = { url };
  writeJson(pathname, root);
  return true;
}

function upsertCodexConfig(pathname, url) {
  const hasSection = (contents, section) =>
    new RegExp(`^\\s*\\[${section}\\]\\s*$`, "m").test(contents);
  const hasNestedMcpServers = (contents) =>
    /^\s*\[mcp_servers\.[^\]]+\]\s*$/m.test(contents);
  const legacyInstructionPath = "~/.docdex/agents.md";
  const parseTomlString = (value) => {
    const trimmed = value.trim();
    const quoted = trimmed.match(/^"(.*)"$/) || trimmed.match(/^'(.*)'$/);
    return quoted ? quoted[1] : trimmed;
  };
  const migrateLegacyMcpServers = (contents) => {
    if (!/\[\[mcp_servers\]\]/m.test(contents)) {
      return { contents, migrated: false };
    }
    const lines = contents.split(/\r?\n/);
    const output = [];
    const entries = [];
    let inBlock = false;
    let current = null;

    for (const line of lines) {
      if (/^\s*\[\[mcp_servers\]\]\s*$/.test(line)) {
        if (current) entries.push(current);
        current = {};
        inBlock = true;
        continue;
      }
      if (inBlock) {
        if (/^\s*\[.+\]\s*$/.test(line)) {
          if (current) entries.push(current);
          current = null;
          inBlock = false;
          output.push(line);
          continue;
        }
        const match = line.match(/^\s*([A-Za-z0-9_.-]+)\s*=\s*(.+?)\s*$/);
        if (match) {
          current[match[1]] = match[2].trim();
        }
        continue;
      }
      output.push(line);
    }
    if (current) entries.push(current);

    const mapLines = [];
    for (const entry of entries) {
      if (!entry.name) continue;
      const name = parseTomlString(entry.name);
      if (!name) continue;
      mapLines.push(`[mcp_servers.${name}]`);
      for (const [key, value] of Object.entries(entry)) {
        if (key === "name") continue;
        mapLines.push(`${key} = ${value}`);
      }
      mapLines.push("");
    }

    if (mapLines.length === 0) {
      return { contents: output.join("\n"), migrated: true };
    }
    if (output.length && output[output.length - 1].trim()) output.push("");
    while (mapLines.length && !mapLines[mapLines.length - 1].trim()) mapLines.pop();
    output.push(...mapLines);
    return { contents: output.join("\n"), migrated: true };
  };

  const upsertDocdexNested = (contents, urlValue) => {
    const lines = contents.split(/\r?\n/);
    const headerRe = /^\s*\[mcp_servers\.docdex\]\s*$/;
    let start = lines.findIndex((line) => headerRe.test(line));
    if (start === -1) {
      if (lines.length && lines[lines.length - 1].trim()) lines.push("");
      lines.push("[mcp_servers.docdex]");
      lines.push(`url = "${urlValue}"`);
      return { contents: lines.join("\n"), updated: true };
    }
    let end = start + 1;
    while (end < lines.length && !/^\s*\[.+\]\s*$/.test(lines[end])) {
      end += 1;
    }
    let updated = false;
    let urlIndex = -1;
    for (let i = start + 1; i < end; i += 1) {
      if (/^\s*url\s*=/.test(lines[i])) {
        urlIndex = i;
        break;
      }
    }
    if (urlIndex === -1) {
      lines.splice(start + 1, 0, `url = "${urlValue}"`);
      updated = true;
    } else if (!lines[urlIndex].includes(`"${urlValue}"`)) {
      lines[urlIndex] = `url = "${urlValue}"`;
      updated = true;
    }
    return { contents: lines.join("\n"), updated };
  };

  const upsertDocdexRoot = (contents, urlValue) => {
    const lines = contents.split(/\r?\n/);
    const headerRe = /^\s*\[mcp_servers\]\s*$/;
    const start = lines.findIndex((line) => headerRe.test(line));
    if (start === -1) {
      if (lines.length && lines[lines.length - 1].trim()) lines.push("");
      lines.push("[mcp_servers]");
      lines.push(`docdex = { url = "${urlValue}" }`);
      return { contents: lines.join("\n"), updated: true };
    }
    let end = start + 1;
    while (end < lines.length && !/^\s*\[.+\]\s*$/.test(lines[end])) {
      end += 1;
    }
    let updated = false;
    let docdexLine = -1;
    for (let i = start + 1; i < end; i += 1) {
      if (/^\s*docdex\s*=/.test(lines[i])) {
        docdexLine = i;
        break;
      }
    }
    if (docdexLine === -1) {
      lines.splice(end, 0, `docdex = { url = "${urlValue}" }`);
      updated = true;
    } else if (!lines[docdexLine].includes(`"${urlValue}"`)) {
      lines[docdexLine] = `docdex = { url = "${urlValue}" }`;
      updated = true;
    }
    return { contents: lines.join("\n"), updated };
  };

  const removeLegacyInstructions = (text) => {
    const lines = text.split(/\r?\n/);
    const output = [];
    let inFeatures = false;
    let featuresHasEntries = false;
    let buffer = [];
    let updated = false;

    const flushFeatures = () => {
      if (!inFeatures) return;
      if (featuresHasEntries) output.push(...buffer);
      inFeatures = false;
      featuresHasEntries = false;
      buffer = [];
    };

    for (const line of lines) {
      const section = line.match(/^\s*\[([^\]]+)\]\s*$/);
      if (section) {
        flushFeatures();
        if (section[1].trim() === "features") {
          inFeatures = true;
          buffer = [line];
          continue;
        }
        output.push(line);
        continue;
      }
      if (inFeatures) {
        const match = line.match(/^\s*experimental_instructions_file\s*=\s*(.+?)\s*$/);
        if (match && parseTomlString(match[1]) === legacyInstructionPath) {
          updated = true;
          continue;
        }
        if (line.trim() && !line.trim().startsWith("#") && /=/.test(line)) {
          featuresHasEntries = true;
        }
        buffer.push(line);
        continue;
      }
      output.push(line);
    }
    flushFeatures();
    return { contents: output.join("\n"), updated };
  };

  let contents = "";
  if (fs.existsSync(pathname)) {
    contents = fs.readFileSync(pathname, "utf8");
  }
  let updated = false;
  if (/\[\[mcp_servers\]\]/m.test(contents)) {
    const migrated = migrateLegacyMcpServers(contents);
    contents = migrated.contents;
    updated = updated || migrated.migrated;
  }

  const cleaned = removeLegacyInstructions(contents);
  contents = cleaned.contents;
  updated = updated || cleaned.updated;

  if (hasNestedMcpServers(contents)) {
    const nested = upsertDocdexNested(contents, url);
    contents = nested.contents;
    updated = updated || nested.updated;
  } else if (hasSection(contents, "mcp_servers")) {
    const root = upsertDocdexRoot(contents, url);
    contents = root.contents;
    updated = updated || root.updated;
  } else {
    const root = upsertDocdexRoot(contents, url);
    contents = root.contents;
    updated = updated || root.updated;
  }

  if (!updated) {
    return false;
  }
  fs.mkdirSync(path.dirname(pathname), { recursive: true });
  fs.writeFileSync(pathname, contents.endsWith("\n") ? contents : `${contents}\n`);
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
        windsurf: path.join(userProfile, ".codeium", "windsurf", "mcp_config.json"),
        cline: path.join(appData, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
        roo: path.join(appData, "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json"),
        continue: path.join(userProfile, ".continue", "config.json"),
        pearai: path.join(userProfile, ".kiro", "settings", "mcp.json"),
        pearai_alt: path.join(userProfile, ".pearai", "mcp.json"),
        void: path.join(appData, "Void", "mcp.json"),
        vscode: path.join(appData, "Code", "User", "mcp.json"),
        zed: path.join(appData, "Zed", "settings.json"),
        codex: path.join(userProfile, ".codex", "config.toml")
      };
    case "darwin":
      return {
        claude: path.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
        cursor: path.join(home, ".cursor", "mcp.json"),
        windsurf: path.join(home, ".codeium", "windsurf", "mcp_config.json"),
        cline: path.join(home, "Library", "Application Support", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
        roo: path.join(home, "Library", "Application Support", "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json"),
        continue: path.join(home, ".continue", "config.json"),
        pearai: path.join(home, ".kiro", "settings", "mcp.json"),
        pearai_alt: path.join(home, ".config", "pearai", "mcp.json"),
        void: path.join(home, "Library", "Application Support", "Void", "mcp.json"),
        vscode: path.join(home, "Library", "Application Support", "Code", "User", "mcp.json"),
        zed: path.join(home, ".config", "zed", "settings.json"),
        codex: path.join(home, ".codex", "config.toml")
      };
    default:
      return {
        claude: path.join(home, ".config", "Claude", "claude_desktop_config.json"),
        cursor: path.join(home, ".cursor", "mcp.json"),
        windsurf: path.join(home, ".codeium", "windsurf", "mcp_config.json"),
        cline: path.join(home, ".config", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
        roo: path.join(home, ".config", "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json"),
        continue: path.join(home, ".continue", "config.json"),
        pearai: path.join(home, ".kiro", "settings", "mcp.json"),
        pearai_alt: path.join(home, ".config", "pearai", "mcp.json"),
        void: path.join(home, ".config", "Void", "mcp.json"),
        vscode: path.join(home, ".config", "Code", "User", "mcp.json"),
        zed: path.join(home, ".config", "zed", "settings.json"),
        codex: path.join(home, ".codex", "config.toml")
      };
  }
}

function clientInstructionPaths() {
  const home = os.homedir();
  const appData = process.env.APPDATA || path.join(home, "AppData", "Roaming");
  const userProfile = process.env.USERPROFILE || home;
  const vscodeGlobalInstructions = path.join(home, ".vscode", "global_instructions.md");
  const vscodeInstructionsDir = path.join(home, ".vscode", "instructions");
  const vscodeInstructionsFile = path.join(vscodeInstructionsDir, "docdex.md");
  const continueRoot = path.join(userProfile, ".continue");
  const continueJson = path.join(continueRoot, "config.json");
  const continueYaml = path.join(continueRoot, "config.yaml");
  const continueYml = path.join(continueRoot, "config.yml");
  const windsurfGlobalRules = path.join(userProfile, ".codeium", "windsurf", "memories", "global_rules.md");
  const rooRules = path.join(home, ".roo", "rules", "docdex.md");
  const pearaiAgent = path.join(home, ".config", "pearai", "agent.md");
  const aiderConfig = path.join(home, ".aider.conf.yml");
  const gooseConfig = path.join(home, ".config", "goose", "config.yaml");
  const openInterpreterConfig = path.join(home, ".openinterpreter", "profiles", "default.yaml");
  const geminiInstructions = path.join(userProfile, ".gemini", "GEMINI.md");
  const claudeInstructions = path.join(userProfile, ".claude", "CLAUDE.md");
  const cursorAgents = path.join(userProfile, ".cursor", "agents.md");
  const cursorAgentsUpper = path.join(userProfile, ".cursor", "AGENTS.md");
  const codexAgents = path.join(userProfile, ".codex", "AGENTS.md");
  switch (process.platform) {
    case "win32":
      return {
        gemini: geminiInstructions,
        claude: claudeInstructions,
        cursorAgents,
        cursorAgentsUpper,
        continue: continueJson,
        continueYaml,
        continueYml,
        zed: path.join(appData, "Zed", "settings.json"),
        vscodeSettings: path.join(appData, "Code", "User", "settings.json"),
        vscodeGlobalInstructions,
        vscodeInstructionsDir,
        vscodeInstructionsFile,
        windsurfGlobalRules,
        rooRules,
        pearaiAgent,
        aiderConfig,
        gooseConfig,
        openInterpreterConfig,
        codexAgents
      };
    case "darwin":
      return {
        gemini: geminiInstructions,
        claude: claudeInstructions,
        cursorAgents,
        cursorAgentsUpper,
        continue: continueJson,
        continueYaml,
        continueYml,
        zed: path.join(home, ".config", "zed", "settings.json"),
        vscodeSettings: path.join(home, "Library", "Application Support", "Code", "User", "settings.json"),
        vscodeGlobalInstructions,
        vscodeInstructionsDir,
        vscodeInstructionsFile,
        windsurfGlobalRules,
        rooRules,
        pearaiAgent,
        aiderConfig,
        gooseConfig,
        openInterpreterConfig,
        codexAgents
      };
    default:
      return {
        gemini: geminiInstructions,
        claude: claudeInstructions,
        cursorAgents,
        cursorAgentsUpper,
        continue: continueJson,
        continueYaml,
        continueYml,
        zed: path.join(home, ".config", "zed", "settings.json"),
        vscodeSettings: path.join(home, ".config", "Code", "User", "settings.json"),
        vscodeGlobalInstructions,
        vscodeInstructionsDir,
        vscodeInstructionsFile,
        windsurfGlobalRules,
        rooRules,
        pearaiAgent,
        aiderConfig,
        gooseConfig,
        openInterpreterConfig,
        codexAgents
      };
  }
}

function sanitizeVersionForFilename(version) {
  if (!version) return null;
  return String(version).replace(/[^0-9A-Za-z._-]/g, "_");
}

function resolveBinaryPath({ binaryPath, env, distBaseDir, distBaseCandidates } = {}) {
  if (binaryPath && fs.existsSync(binaryPath)) return binaryPath;
  try {
    const platformKey = detectPlatformKey();
    const isWin32 = process.platform === "win32";
    const resolvedVersion = sanitizeVersionForFilename(
      normalizeVersion(resolvePackageVersion())
    );
    const resolvedDistBaseDir = distBaseDir || resolveDistBaseDir({ env, fsModule: fs });
    const binDir = resolveBinDir({ env, distBaseDir: resolvedDistBaseDir });
    const baseCandidates = distBaseCandidates || resolveDistBaseCandidates({ env });
    const candidates = [];
    if (binDir) {
      if (isWin32 && resolvedVersion) {
        candidates.push(path.join(binDir, `docdexd-${resolvedVersion}.exe`));
      }
      candidates.push(path.join(binDir, isWin32 ? "docdexd.exe" : "docdexd"));
    }
    for (const base of baseCandidates) {
      candidates.push(path.join(base, platformKey, isWin32 ? "docdexd.exe" : "docdexd"));
    }
    candidates.push(
      path.join(__dirname, "..", "dist", platformKey, isWin32 ? "docdexd.exe" : "docdexd")
    );
    for (const candidate of candidates) {
      if (candidate && fs.existsSync(candidate)) return candidate;
    }
  } catch (err) {
    if (!(err instanceof UnsupportedPlatformError)) throw err;
  }
  return null;
}

function isPathWithin(parent, candidate) {
  const base = path.resolve(parent);
  const target = path.resolve(candidate);
  if (base === target) return true;
  return target.startsWith(base + path.sep);
}

function isMacProtectedPath(candidate) {
  if (process.platform !== "darwin") return false;
  const home = os.homedir();
  return ["Desktop", "Documents", "Downloads"].some((dir) => isPathWithin(path.join(home, dir), candidate));
}

function ensureStartupBinary(binaryPath, { logger, env, distBaseDir } = {}) {
  if (!binaryPath) return null;
  const isWin32 = process.platform === "win32";
  const mustCopy = isWin32 || isMacProtectedPath(binaryPath) || isTempPath(binaryPath);
  if (!mustCopy) return binaryPath;
  const binDir = resolveBinDir({ env, distBaseDir });
  const resolvedVersion = sanitizeVersionForFilename(
    normalizeVersion(resolvePackageVersion())
  );
  const targetName = isWin32 && resolvedVersion
    ? `docdexd-${resolvedVersion}.exe`
    : path.basename(binaryPath);
  const target = path.join(binDir, targetName);
  if (fs.existsSync(target)) return target;
  try {
    fs.mkdirSync(binDir, { recursive: true });
    fs.copyFileSync(binaryPath, target);
    if (!isWin32) {
      fs.chmodSync(target, 0o755);
    }
    return target;
  } catch (err) {
    logger?.warn?.(`[docdex] failed to stage daemon binary for startup: ${err?.message || err}`);
    return binaryPath;
  }
}

function resolveStartupBinaryPaths({ binaryPath, logger, env, distBaseDir } = {}) {
  const resolvedBinary = ensureStartupBinary(binaryPath, { logger, env, distBaseDir });
  return { binaryPath: resolvedBinary };
}

function applyAgentInstructions({ logger } = {}) {
  const instructions = buildDocdexInstructionBlock(loadAgentInstructions());
  if (!normalizeInstructionText(instructions)) return { ok: false, reason: "missing_instructions" };
  const paths = clientInstructionPaths();
  let updated = false;
  const safeApply = (label, fn) => {
    try {
      const didUpdate = fn();
      if (didUpdate) updated = true;
      return didUpdate;
    } catch (err) {
      logger?.warn?.(`[docdex] agent instructions update failed for ${label}: ${err?.message || err}`);
      return false;
    }
  };

  if (paths.vscodeGlobalInstructions) {
    safeApply("vscode-global-cleanup", () => removePromptFile(paths.vscodeGlobalInstructions));
  }
  if (paths.vscodeInstructionsFile) {
    safeApply("vscode-instructions-file-cleanup", () =>
      removePromptFile(paths.vscodeInstructionsFile)
    );
  }
  if (paths.cursorAgents) {
    safeApply("cursor-legacy-cleanup", () => removePromptFile(paths.cursorAgents));
  }
  if (paths.cursorAgentsUpper) {
    safeApply("cursor-legacy-upper-cleanup", () => removePromptFile(paths.cursorAgentsUpper));
  }
  if (paths.vscodeSettings) {
    safeApply("vscode-settings", () =>
      upsertVsCodeInstructions(paths.vscodeSettings, instructions, paths.vscodeGlobalInstructions)
    );
  }
  if (paths.windsurfGlobalRules) {
    safeApply("windsurf", () => upsertPromptFile(paths.windsurfGlobalRules, instructions, { prepend: true }));
  }
  if (paths.rooRules) {
    safeApply("roo", () => upsertPromptFile(paths.rooRules, instructions));
  }
  if (paths.pearaiAgent) {
    safeApply("pearai", () => upsertPromptFile(paths.pearaiAgent, instructions, { prepend: true }));
  }
  if (paths.claude) {
    safeApply("claude", () => upsertClaudeInstructions(paths.claude, instructions));
  }
  if (paths.gemini) {
    safeApply("gemini", () => upsertPromptFile(paths.gemini, instructions));
  }
  const continueYamlExists =
    (paths.continueYaml && fs.existsSync(paths.continueYaml)) ||
    (paths.continueYml && fs.existsSync(paths.continueYml));
  if (continueYamlExists) {
    if (paths.continueYaml && fs.existsSync(paths.continueYaml)) {
      safeApply("continue-yaml", () => upsertContinueYamlRules(paths.continueYaml, instructions));
    }
    if (paths.continueYml && fs.existsSync(paths.continueYml)) {
      safeApply("continue-yml", () => upsertContinueYamlRules(paths.continueYml, instructions));
    }
    if (paths.continue && fs.existsSync(paths.continue)) {
      safeApply("continue-json", () => upsertContinueJsonInstructions(paths.continue, instructions));
    }
  } else if (paths.continue) {
    safeApply("continue-json", () => upsertContinueJsonInstructions(paths.continue, instructions));
  }
  if (paths.zed) {
    safeApply("zed", () => upsertZedInstructions(paths.zed, instructions));
  }
  if (paths.openInterpreterConfig) {
    safeApply("open-interpreter", () =>
      upsertYamlInstruction(paths.openInterpreterConfig, "system_message", instructions)
    );
  }
  if (paths.codexAgents) {
    safeApply("codex", () => upsertPromptFile(paths.codexAgents, instructions));
  }

  return { ok: true, updated };
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

function hasInteractiveTty(stdin, stdout) {
  return Boolean((stdin && stdin.isTTY) || (stdout && stdout.isTTY));
}

function canPromptWithTty(stdin, stdout) {
  if (hasInteractiveTty(stdin, stdout)) return true;
  const isWindows = process.platform === "win32";
  const inputPath = isWindows ? "CONIN$" : "/dev/tty";
  const outputPath = isWindows ? "CONOUT$" : "/dev/tty";
  try {
    const readFd = fs.openSync(inputPath, "r");
    const writeFd = fs.openSync(outputPath, "w");
    const readable = tty.isatty(readFd);
    const writable = tty.isatty(writeFd);
    fs.closeSync(readFd);
    fs.closeSync(writeFd);
    return readable && writable;
  } catch {
    return false;
  }
}

function resolveOllamaInstallMode({
  env = process.env,
  stdin = process.stdin,
  stdout = process.stdout,
  canPrompt = canPromptWithTty
} = {}) {
  const override = parseEnvBool(env.DOCDEX_OLLAMA_INSTALL);
  if (override === true) return { mode: "install", reason: "env", interactive: false };
  if (override === false) return { mode: "skip", reason: "env", interactive: false };
  if (!canPrompt(stdin, stdout)) {
    if (env.CI) return { mode: "skip", reason: "ci", interactive: false };
    return { mode: "skip", reason: "non_interactive", interactive: false };
  }
  return { mode: "prompt", reason: "interactive", interactive: true };
}

function resolveOllamaModelPromptMode({
  env = process.env,
  stdin = process.stdin,
  stdout = process.stdout,
  canPrompt = canPromptWithTty
} = {}) {
  const override = parseEnvBool(env.DOCDEX_OLLAMA_MODEL_PROMPT);
  if (override === true) return { mode: "prompt", reason: "env", interactive: true };
  if (override === false) return { mode: "skip", reason: "env", interactive: false };
  const assumeYes = parseEnvBool(env.DOCDEX_OLLAMA_MODEL_ASSUME_Y);
  if (assumeYes === true) return { mode: "auto", reason: "env", interactive: false };
  if (!canPrompt(stdin, stdout)) {
    if (env.CI) return { mode: "skip", reason: "ci", interactive: false };
    return { mode: "skip", reason: "non_interactive", interactive: false };
  }
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

function isEmbeddingModelName(name) {
  const normalized = normalizeModelName(name).toLowerCase();
  if (!normalized) return false;
  const base = normalized.split(":")[0];
  const embed = DEFAULT_OLLAMA_MODEL.toLowerCase();
  return base === embed || base.startsWith(`${embed}-`);
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

function resolvePromptStreams(stdin, stdout) {
  if (hasInteractiveTty(stdin, stdout)) {
    return { input: stdin, output: stdout, close: null };
  }
  const isWindows = process.platform === "win32";
  const inputPath = isWindows ? "CONIN$" : "/dev/tty";
  const outputPath = isWindows ? "CONOUT$" : "/dev/tty";
  try {
    const readFd = fs.openSync(inputPath, "r");
    const writeFd = fs.openSync(outputPath, "w");
    if (!tty.isatty(readFd) || !tty.isatty(writeFd)) {
      fs.closeSync(readFd);
      fs.closeSync(writeFd);
      return { input: stdin, output: stdout, close: null };
    }
    const input = fs.createReadStream(inputPath, { fd: readFd, autoClose: true });
    const output = fs.createWriteStream(outputPath, { fd: writeFd, autoClose: true });
    return {
      input,
      output,
      close: () => {
        input.close();
        output.end();
      }
    };
  } catch {
    return { input: stdin, output: stdout, close: null };
  }
}

function promptYesNo(question, { defaultYes = true, stdin = process.stdin, stdout = process.stdout } = {}) {
  return new Promise((resolve) => {
    const { input, output, close } = resolvePromptStreams(stdin, stdout);
    const rl = readline.createInterface({ input, output, terminal: Boolean(output?.isTTY) });
    if (output && typeof output.write === "function") {
      output.write(`\n${question}`);
    }
    rl.question("", (answer) => {
      rl.close();
      if (typeof close === "function") close();
      const normalized = String(answer || "").trim().toLowerCase();
      if (!normalized) return resolve(defaultYes);
      resolve(["y", "yes"].includes(normalized));
    });
  });
}

function promptInput(question, { stdin = process.stdin, stdout = process.stdout } = {}) {
  return new Promise((resolve) => {
    const { input, output, close } = resolvePromptStreams(stdin, stdout);
    const rl = readline.createInterface({ input, output, terminal: Boolean(output?.isTTY) });
    if (output && typeof output.write === "function") {
      output.write(`\n${question}`);
    }
    rl.question("", (answer) => {
      rl.close();
      if (typeof close === "function") close();
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
    if (isEmbeddingModelName(forced)) {
      logger?.warn?.(`[docdex] ${forced} is an embedding-only model; choose a chat model.`);
      return { status: "skipped", reason: "embedding_only" };
    }
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
  const displayModels = normalizedInstalled.map((model) => {
    const selectable = !isEmbeddingModelName(model);
    return {
      model,
      label: selectable ? model : `${model} (embedding only)`,
      selectable
    };
  });
  const selectableModels = displayModels.filter((item) => item.selectable).map((item) => item.model);
  const installedLower = normalizedInstalled.map((model) => model.toLowerCase());
  const hasPhi = installedLower.includes(phiModel.toLowerCase());
  const defaultLower = defaultChoice ? defaultChoice.toLowerCase() : null;
  const selectionDefault = defaultLower && selectableModels.some((model) => model.toLowerCase() === defaultLower)
    ? defaultChoice
    : selectableModels[0];

  if (decision.mode === "auto") {
    if (selectionDefault) {
      updateDefaultModelConfig(configPath, selectionDefault, logger);
      return { status: "selected", model: selectionDefault };
    }
    return { status: "skipped", reason: "no_models" };
  }

  stdout.write("[docdex] Ollama models detected:\n");
  displayModels.forEach((item, idx) => {
    const marker = item.model === selectionDefault ? " (default)" : "";
    stdout.write(`  ${idx + 1}) ${item.label}${marker}\n`);
  });
  if (!hasPhi) {
    stdout.write(`  I) Install ${phiModel} (~${sizeText}, free ${freeText})\n`);
  }
  stdout.write("  S) Skip\n");

  const defaultHint = selectionDefault ? ` [${selectionDefault}]` : "";
  const answer = await promptInput(
    `[docdex] Select default model${defaultHint}: `,
    { stdin, stdout }
  );
  const normalizedAnswer = normalizeModelName(answer);
  const answerLower = normalizedAnswer.toLowerCase();
  if (!answer) {
    if (selectionDefault) {
      updateDefaultModelConfig(configPath, selectionDefault, logger);
      return { status: "selected", model: selectionDefault };
    }
    return { status: "skipped", reason: "no_models" };
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
  if (isEmbeddingModelName(normalizedAnswer)) {
    const modelName = normalizedAnswer || DEFAULT_OLLAMA_MODEL;
    logger?.warn?.(`[docdex] ${modelName} is an embedding-only model; choose a chat model.`);
    return { status: "skipped", reason: "embedding_only" };
  }
  const numeric = Number.parseInt(answerLower, 10);
  if (Number.isFinite(numeric) && numeric >= 1 && numeric <= displayModels.length) {
    const selected = displayModels[numeric - 1];
    if (!selected.selectable) {
      logger?.warn?.(`[docdex] ${selected.model} is an embedding-only model; choose a chat model.`);
      return { status: "skipped", reason: "embedding_only" };
    }
    updateDefaultModelConfig(configPath, selected.model, logger);
    return { status: "selected", model: selected.model };
  }
  const matchedIndex = installedLower.indexOf(answerLower);
  if (matchedIndex !== -1) {
    const selected = displayModels[matchedIndex];
    if (!selected.selectable) {
      logger?.warn?.(`[docdex] ${selected.model} is an embedding-only model; choose a chat model.`);
      return { status: "skipped", reason: "embedding_only" };
    }
    updateDefaultModelConfig(configPath, selected.model, logger);
    return { status: "selected", model: selected.model };
  }
  logger?.warn?.("[docdex] Unrecognized selection; skipping model update.");
  return { status: "skipped", reason: "invalid_selection" };
}

function envBool(value) {
  if (!value) return false;
  const normalized = String(value).trim().toLowerCase();
  return ["1", "true", "t", "yes", "y", "on"].includes(normalized);
}

function isTempPath(value, osModule = os) {
  if (!value) return false;
  const tmpdir = osModule.tmpdir();
  if (!tmpdir) return false;
  const resolvedValue = path.resolve(value);
  const resolvedTmp = path.resolve(tmpdir);
  return resolvedValue === resolvedTmp || resolvedValue.startsWith(resolvedTmp + path.sep);
}

function buildDaemonEnvPairs() {
  return [["DOCDEX_BROWSER_AUTO_INSTALL", "0"]];
}

function buildDaemonEnv() {
  return Object.fromEntries(buildDaemonEnvPairs());
}

function escapeCmdArg(value) {
  return `"${String(value).replace(/"/g, "\"\"")}"`;
}

function writeWindowsRunner({ binaryPath, args, envPairs, workingDir, logger, distBaseDir } = {}) {
  const runnerPath = resolveWindowsRunnerPath({ distBaseDir });
  const lines = ["@echo off", "setlocal"];
  for (const [key, value] of envPairs || []) {
    lines.push(`set "${key}=${value}"`);
  }
  if (workingDir) {
    lines.push(`cd /d ${escapeCmdArg(workingDir)}`);
  }
  const argString = (args || []).map((arg) => escapeCmdArg(arg)).join(" ");
  lines.push(`${escapeCmdArg(binaryPath)} ${argString}`.trim());
  try {
    fs.mkdirSync(path.dirname(runnerPath), { recursive: true });
    fs.writeFileSync(runnerPath, `${lines.join("\r\n")}\r\n`);
    return runnerPath;
  } catch (err) {
    logger?.warn?.(`[docdex] failed to write Windows runner: ${err?.message || err}`);
    return null;
  }
}

function writeWindowsSetupRunner({ binaryPath, args, logger, distBaseDir } = {}) {
  if (!binaryPath) return null;
  const runnerPath = resolveWindowsSetupRunnerPath({ distBaseDir });
  const lines = [
    "@echo off",
    "setlocal",
    "set \"DOCDEX_SETUP_AUTO=1\"",
    "set \"DOCDEX_SETUP_MODE=auto\""
  ];
  const argString = (args || []).map((arg) => escapeCmdArg(arg)).join(" ");
  lines.push(`${escapeCmdArg(binaryPath)} ${argString}`.trim());
  try {
    fs.mkdirSync(path.dirname(runnerPath), { recursive: true });
    fs.writeFileSync(runnerPath, `${lines.join("\r\n")}\r\n`);
    return runnerPath;
  } catch (err) {
    logger?.warn?.(`[docdex] failed to write Windows setup runner: ${err?.message || err}`);
    return null;
  }
}

function registerStartup({ binaryPath, port, repoRoot, logger, distBaseDir, startNow = true }) {
  if (!binaryPath) return { ok: false, reason: "missing_binary" };
  if (startNow) {
    stopDaemonService({ logger });
  }
  const envPairs = buildDaemonEnvPairs();
  const workingDir = repoRoot ? path.resolve(repoRoot) : null;
  const args = [
    "daemon",
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
    const envVars = envPairs.flatMap(([key, value]) => [
      `    <key>${key}</key>\n`,
      `    <string>${value}</string>\n`
    ]);
    const plist = `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n` +
      `<plist version="1.0">\n` +
      `<dict>\n` +
      `  <key>Label</key>\n` +
      `  <string>com.docdex.daemon</string>\n` +
      `  <key>EnvironmentVariables</key>\n` +
      `  <dict>\n` +
      envVars.join("") +
      `  </dict>\n` +
      `  <key>ProgramArguments</key>\n` +
      `  <array>\n` +
      programArgs.map((arg) => `    <string>${arg}</string>\n`).join("") +
      `  </array>\n` +
      (workingDir
        ? `  <key>WorkingDirectory</key>\n` + `  <string>${workingDir}</string>\n`
        : "") +
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
    if (!startNow) return { ok: true };
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
    const envLines = envPairs.map(([key, value]) => `Environment=${key}=${value}`);
    const unit = [
      "[Unit]",
      "Description=Docdex daemon",
      "After=network.target",
      "",
      "[Service]",
      `ExecStart=${binaryPath} ${args.join(" ")}`,
      workingDir ? `WorkingDirectory=${workingDir}` : "",
      ...envLines,
      "Restart=always",
      "RestartSec=2",
      "",
      "[Install]",
      "WantedBy=default.target",
      ""
    ].filter(Boolean).join("\n");
    fs.writeFileSync(unitPath, unit);
    const reload = spawnSync("systemctl", ["--user", "daemon-reload"]);
    const enableArgs = startNow
      ? ["--user", "enable", "--now", "docdexd.service"]
      : ["--user", "enable", "docdexd.service"];
    const enable = spawnSync("systemctl", enableArgs);
    ensureSystemdUserLinger({ logger });
    if (reload.status === 0 && enable.status === 0) return { ok: true };
    logger?.warn?.(`[docdex] systemd failed: ${enable.stderr || reload.stderr || "unknown error"}`);
    return { ok: false, reason: "systemd_failed" };
  }

  if (process.platform === "win32") {
    const taskName = "Docdex Daemon";
    const runnerPath = writeWindowsRunner({
      binaryPath,
      args,
      envPairs,
      workingDir,
      logger,
      distBaseDir
    });
    if (!runnerPath) return { ok: false, reason: "runner_failed" };
    const taskArgs = `cmd.exe /c ${escapeCmdArg(runnerPath)}`;
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
      if (startNow) {
        spawnSync("schtasks", ["/Run", "/TN", taskName]);
      }
      return { ok: true };
    }
    logger?.warn?.(`[docdex] schtasks failed: ${create.stderr || "unknown error"}`);
    return { ok: false, reason: "schtasks_failed" };
  }

  return { ok: false, reason: "unsupported_platform" };
}

async function startDaemonWithHealthCheck({ binaryPath, port, host, logger, distBaseDir, startNow = true }) {
  const startup = registerStartup({
    binaryPath,
    port,
    repoRoot: daemonRootPath(),
    logger,
    distBaseDir,
    startNow
  });
  if (!startup.ok) {
    logger?.warn?.(`[docdex] daemon service registration failed (${startup.reason || "unknown"}).`);
    return { ok: false, reason: "startup_failed" };
  }
  if (!startNow) {
    return { ok: true, reason: "registered" };
  }
  startDaemonService({ logger });
  const healthy = await waitForDaemonHealthy({ host, port });
  if (healthy) {
    return { ok: true, reason: "healthy" };
  }
  logger?.warn?.(`[docdex] daemon failed health check on ${host}:${port}`);
  stopDaemonService({ logger });
  stopDaemonFromLock({ logger });
  stopDaemonByName({ logger });
  clearDaemonLocks();
  return { ok: false, reason: "health_failed" };
}

function recordStartupFailure(details) {
  const markerPath = path.join(stateDir(), STARTUP_FAILURE_MARKER);
  fs.mkdirSync(path.dirname(markerPath), { recursive: true });
  fs.writeFileSync(markerPath, JSON.stringify(details, null, 2));
}

function recordSetupPending(details) {
  const markerPath = setupPendingPath();
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

function isNpmLifecycle(env = process.env) {
  if (env?.npm_lifecycle_event) return true;
  const userAgent = String(env?.npm_config_user_agent || "");
  if (userAgent.includes("npm/")) return true;
  if (env?.npm_execpath) return true;
  return false;
}

function shouldSkipDaemonSideEffects({ env = process.env, skipDaemon } = {}) {
  if (skipDaemon) return true;
  if (parseEnvBool(env?.DOCDEX_DAEMON_SKIP_SETUP)) return true;
  return false;
}

function shouldSkipSetup(env = process.env) {
  return parseEnvBool(env.DOCDEX_SETUP_SKIP) === true;
}

function commandExists(cmd, spawnSyncFn) {
  const result = spawnSyncFn(cmd, ["--version"], { stdio: "ignore" });
  if (result?.error?.code === "ENOENT") return false;
  return true;
}

function currentUsername() {
  try {
    const info = os.userInfo();
    if (info && info.username) return info.username;
  } catch {}
  return process.env.USER || process.env.LOGNAME || process.env.USERNAME || null;
}

function ensureSystemdUserLinger({ logger } = {}) {
  if (process.platform !== "linux") return { ok: false, reason: "unsupported_platform" };
  if (!commandExists("loginctl", spawnSync)) return { ok: false, reason: "loginctl_missing" };
  const username = currentUsername();
  if (!username) return { ok: false, reason: "username_missing" };
  const result = spawnSync("loginctl", ["enable-linger", username]);
  if (result.status === 0) return { ok: true };
  logger?.warn?.(`[docdex] loginctl enable-linger failed: ${result.stderr || "unknown error"}`);
  return { ok: false, reason: "loginctl_failed" };
}

function launchMacTerminal({ binaryPath, args, spawnSyncFn, logger }) {
  const command = [
    "DOCDEX_SETUP_AUTO=1",
    "DOCDEX_SETUP_MODE=auto",
    `"${binaryPath}"`,
    ...args.map((arg) => `"${arg}"`)
  ].join(" ");
  const script = [
    'tell application "Terminal"',
    'if not (exists window 1) then',
    `do script ${JSON.stringify(command)}`,
    "else",
    `do script ${JSON.stringify(command)} in window 1`,
    "end if",
    "activate",
    "end tell"
  ].join("\n");
  const result = spawnSyncFn("osascript", ["-e", script]);
  if (result.status === 0) return true;
  logger?.warn?.(`[docdex] osascript launch failed: ${result.stderr || "unknown error"}`);
  return false;
}

function launchLinuxTerminal({ binaryPath, args, spawnFn, spawnSyncFn }) {
  const envArgs = ["env", "DOCDEX_SETUP_AUTO=1", "DOCDEX_SETUP_MODE=auto", binaryPath, ...args];
  const candidates = [
    { cmd: "x-terminal-emulator", args: ["-e", ...envArgs] },
    { cmd: "gnome-terminal", args: ["--", ...envArgs] },
    { cmd: "konsole", args: ["-e", ...envArgs] },
    { cmd: "xfce4-terminal", args: ["-e", ...envArgs] },
    { cmd: "xterm", args: ["-e", ...envArgs] },
    { cmd: "kitty", args: ["-e", ...envArgs] },
    { cmd: "alacritty", args: ["-e", ...envArgs] },
    { cmd: "wezterm", args: ["start", "--", ...envArgs] }
  ];
  for (const candidate of candidates) {
    if (!commandExists(candidate.cmd, spawnSyncFn)) continue;
    const child = spawnFn(candidate.cmd, candidate.args, {
      stdio: "ignore",
      detached: true
    });
    if (child?.pid) {
      child.unref?.();
      return true;
    }
  }
  return false;
}

function launchSetupWizard({
  binaryPath,
  logger,
  env = process.env,
  stdin = process.stdin,
  stdout = process.stdout,
  spawnFn = spawn,
  spawnSyncFn = spawnSync,
  platform = process.platform,
  canPrompt = canPromptWithTty,
  distBaseDir
}) {
  if (!binaryPath) return { ok: false, reason: "missing_binary" };
  if (shouldSkipSetup(env)) return { ok: false, reason: "skipped" };

  const args = ["setup", "--auto"];
  if (platform === "linux" || platform === "darwin") {
    if (!canPrompt(stdin, stdout)) {
      return { ok: false, reason: "non_interactive" };
    }
    if (platform === "darwin") {
      return launchMacTerminal({ binaryPath, args, spawnSyncFn, logger })
        ? { ok: true }
        : { ok: false, reason: "terminal_launch_failed" };
    }
    return launchLinuxTerminal({ binaryPath, args, spawnFn, spawnSyncFn })
      ? { ok: true }
      : { ok: false, reason: "terminal_launch_failed" };
  }

  if (platform === "win32") {
    if (!canPrompt(stdin, stdout)) {
      return { ok: false, reason: "non_interactive" };
    }
    const runnerPath = writeWindowsSetupRunner({
      binaryPath,
      args,
      logger,
      distBaseDir
    });
    if (!runnerPath) return { ok: false, reason: "runner_failed" };
    const result = spawnSyncFn("cmd", [
      "/c",
      "start",
      "",
      "cmd",
      "/c",
      escapeCmdArg(runnerPath)
    ]);
    if (result.status === 0) return { ok: true };
    logger?.warn?.(`[docdex] cmd start failed: ${result.stderr || "unknown error"}`);
    return { ok: false, reason: "terminal_launch_failed" };
  }

  return { ok: false, reason: "unsupported_platform" };
}

async function runPostInstallSetup({ binaryPath, logger, env, skipDaemon, distBaseDir } = {}) {
  const log = logger || console;
  const effectiveEnv = env || process.env;
  const isNpm = isNpmLifecycle(effectiveEnv);
  const distCandidates = resolveDistBaseCandidates({ env: effectiveEnv });
  const resolvedDistBaseDir = distBaseDir || resolveDistBaseDir({ env: effectiveEnv, fsModule: fs });
  let allowDaemon = !shouldSkipDaemonSideEffects({ env: effectiveEnv, skipDaemon });
  const configPath = defaultConfigPath();
  let existingConfig = "";
  if (fs.existsSync(configPath)) {
    existingConfig = fs.readFileSync(configPath, "utf8");
  }
  const port = DEFAULT_DAEMON_PORT;
  let portState = { available: true, reuseExisting: false };
  if (allowDaemon) {
    const cleaned = await cleanupExistingDaemon({
      logger: log,
      env: effectiveEnv,
      distBaseDir: resolvedDistBaseDir,
      host: DEFAULT_HOST,
      port
    });
    if (!cleaned) {
      log.warn?.(
        `[docdex] ${DEFAULT_HOST}:${port} is still in use after removing the daemon service; skipping daemon startup.`
      );
      recordStartupFailure({ reason: "port_in_use", host: DEFAULT_HOST, port });
      allowDaemon = false;
    }
  }
  if (allowDaemon) {
    portState = await resolveDaemonPortState({
      host: DEFAULT_HOST,
      port,
      logger: log
    });
    if (!portState.available && !portState.reuseExisting) {
      log.warn?.(
        `[docdex] ${DEFAULT_HOST}:${port} is already in use; skipping daemon startup. Run \`docdexd daemon\` after freeing the port.`
      );
      recordStartupFailure({ reason: "port_in_use", host: DEFAULT_HOST, port });
      allowDaemon = false;
    }
  }

  const daemonRoot = ensureDaemonRoot();
  const resolvedBinary = resolveBinaryPath({
    binaryPath,
    env: effectiveEnv,
    distBaseDir: resolvedDistBaseDir,
    distBaseCandidates: distCandidates
  });
  const startupBinaries = resolveStartupBinaryPaths({
    binaryPath: resolvedBinary,
    logger: log,
    env: effectiveEnv,
    distBaseDir: resolvedDistBaseDir
  });
  let reuseExisting = allowDaemon ? portState.reuseExisting : false;
  if (reuseExisting && allowDaemon) {
    const daemonInfo = await fetchDaemonInfo({ host: DEFAULT_HOST, port });
    const daemonVersion = normalizeVersion(daemonInfo?.version);
    const packageVersion = normalizeVersion(resolvePackageVersion());
    if (daemonInfo?.product === "Docdex" && daemonVersion && packageVersion) {
      if (daemonVersion !== packageVersion) {
        log.warn?.(
          `[docdex] daemon version ${daemonVersion} differs from package ${packageVersion}; restarting daemon.`
        );
        stopDaemonService({ logger: log });
        stopDaemonFromLock({ logger: log });
        stopDaemonByName({ logger: log });
        clearDaemonLocks();
        const released = await waitForPortAvailable({
          host: DEFAULT_HOST,
          port
        });
        if (!released) {
          log.warn?.("[docdex] daemon restart failed; port still in use.");
          recordStartupFailure({ reason: "restart_failed", host: DEFAULT_HOST, port });
          allowDaemon = false;
        }
        reuseExisting = false;
      }
    }
  }
  let startupOk = false;
  if (allowDaemon) {
    const allowStartNow = !(process.platform === "win32" && isNpm);
    const result = await startDaemonWithHealthCheck({
      binaryPath: startupBinaries.binaryPath,
      port,
      host: DEFAULT_HOST,
      logger: log,
      distBaseDir: resolvedDistBaseDir,
      startNow: !reuseExisting && allowStartNow
    });
    if (!result.ok) {
      log.warn?.(`[docdex] daemon failed to start on ${DEFAULT_HOST}:${port}.`);
      recordStartupFailure({ reason: result.reason || "startup_failed", host: DEFAULT_HOST, port });
      allowDaemon = false;
    } else {
      startupOk = true;
    }
  }

  const httpBindAddr = `${DEFAULT_HOST}:${port}`;
  const nextConfig = upsertServerConfig(existingConfig || "", httpBindAddr);
  if (!existingConfig || existingConfig !== nextConfig) {
    fs.mkdirSync(path.dirname(configPath), { recursive: true });
    fs.writeFileSync(configPath, nextConfig);
  }

  const url = configUrlForPort(port);
  const codexUrl = configStreamableUrlForPort(port);
  const paths = clientConfigPaths();
  const jsonPaths = [
    paths.claude,
    paths.cursor,
    paths.windsurf,
    paths.cline,
    paths.roo,
    paths.continue,
    paths.pearai,
    paths.pearai_alt,
    paths.void,
    paths.vscode
  ].filter(Boolean);
  for (const jsonPath of jsonPaths) {
    upsertMcpServerJson(jsonPath, url);
  }
  if (paths.zed) {
    upsertZedConfig(paths.zed, url);
  }
  upsertCodexConfig(paths.codex, codexUrl);
  applyAgentInstructions({ logger: log });
  if (startupOk) {
    clearStartupFailure();
  }
  const skipExplicit = shouldSkipSetup(effectiveEnv);
  const skipWizard = isNpm || skipExplicit;
  const setupLaunch = skipWizard
    ? { ok: false, reason: skipExplicit ? "skipped" : "npm_lifecycle" }
    : launchSetupWizard({
        binaryPath: startupBinaries.binaryPath,
        logger: log,
        distBaseDir: resolvedDistBaseDir
      });
  if (!setupLaunch.ok) {
    if (setupLaunch.reason !== "skipped") {
      log.warn?.("[docdex] setup wizard did not launch. Run `docdex setup`.");
      recordSetupPending({ reason: setupLaunch.reason, port, repoRoot: daemonRoot });
    }
  }
  return { port, url, configPath };
}

module.exports = {
  runPostInstallSetup,
  upsertServerConfig,
  parseServerBind,
  upsertMcpServerJson,
  upsertZedConfig,
  upsertCodexConfig,
  configUrlForPort,
  configStreamableUrlForPort,
  parseEnvBool,
  resolveOllamaInstallMode,
  resolveOllamaModelPromptMode,
  parseOllamaListOutput,
  formatGiB,
  readLlmDefaultModel,
  upsertLlmDefaultModel,
  pullOllamaModel,
  listOllamaModels,
  hasInteractiveTty,
  canPromptWithTty,
  shouldSkipSetup,
  launchSetupWizard,
  applyAgentInstructions,
  buildDaemonEnv,
  resolveDaemonPortState,
  normalizeVersion
};
