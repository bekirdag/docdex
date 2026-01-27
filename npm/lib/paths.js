"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

function resolveUserDataDir({
  env = process.env,
  platform = process.platform,
  homedir = os.homedir,
  pathModule = path
} = {}) {
  const home = typeof homedir === "function" ? homedir() : os.homedir();
  if (platform === "win32") {
    const base = env?.LOCALAPPDATA || pathModule.join(home, "AppData", "Local");
    return pathModule.resolve(base);
  }
  if (platform === "darwin") {
    return pathModule.join(home, "Library", "Application Support");
  }
  const xdg = env?.XDG_DATA_HOME;
  if (xdg && String(xdg).trim()) return pathModule.resolve(String(xdg).trim());
  return pathModule.join(home, ".local", "share");
}

function resolveDocdexDataDir(options = {}) {
  const pathModule = options.pathModule || path;
  return pathModule.join(resolveUserDataDir({ ...options, pathModule }), "docdex");
}

function resolveDistBaseCandidates(options = {}) {
  const env = options.env || process.env;
  const pathModule = options.pathModule || path;
  const override = env?.DOCDEX_DIST_DIR;
  if (override && String(override).trim()) {
    return [pathModule.resolve(String(override).trim())];
  }
  const candidates = [];
  const primary = pathModule.join(resolveDocdexDataDir({ ...options, pathModule }), "dist");
  if (primary) candidates.push(primary);
  const homedir = typeof options.homedir === "function" ? options.homedir : os.homedir;
  const home = homedir ? homedir() : os.homedir();
  if (home) {
    const fallback = pathModule.join(home, ".docdex", "dist");
    if (!candidates.includes(fallback)) candidates.push(fallback);
  }
  return candidates;
}

function findExistingParent(candidate, fsModule, pathModule) {
  if (!candidate) return null;
  let current = pathModule.resolve(candidate);
  while (current && !fsModule.existsSync(current)) {
    const parent = pathModule.dirname(current);
    if (parent === current) return null;
    current = parent;
  }
  return current;
}

function canWritePath(candidate, fsModule) {
  if (!fsModule?.accessSync) return true;
  const mode = fsModule.constants?.W_OK ?? 0o2;
  try {
    fsModule.accessSync(candidate, mode);
    return true;
  } catch {
    return false;
  }
}

function resolveDistBaseDir(options = {}) {
  const fsModule = options.fsModule || fs;
  const pathModule = options.pathModule || path;
  const candidates = resolveDistBaseCandidates({ ...options, pathModule });
  if (!candidates.length) {
    return pathModule.join(resolveDocdexDataDir({ ...options, pathModule }), "dist");
  }
  for (const candidate of candidates) {
    if (!fsModule?.existsSync) return candidate;
    const parent = findExistingParent(candidate, fsModule, pathModule);
    if (parent && canWritePath(parent, fsModule)) {
      return candidate;
    }
  }
  return candidates[0];
}

function resolveBinDir(options = {}) {
  const pathModule = options.pathModule || path;
  if (options.distBaseDir) {
    return pathModule.join(pathModule.dirname(options.distBaseDir), "bin");
  }
  return pathModule.join(resolveDocdexDataDir({ ...options, pathModule }), "bin");
}

function resolveWindowsRunnerPath(options = {}) {
  const pathModule = options.pathModule || path;
  if (options.distBaseDir) {
    return pathModule.join(pathModule.dirname(options.distBaseDir), "run-daemon.cmd");
  }
  return pathModule.join(resolveDocdexDataDir({ ...options, pathModule }), "run-daemon.cmd");
}

module.exports = {
  resolveUserDataDir,
  resolveDocdexDataDir,
  resolveDistBaseCandidates,
  resolveDistBaseDir,
  resolveBinDir,
  resolveWindowsRunnerPath
};
