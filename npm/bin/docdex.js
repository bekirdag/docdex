#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawn } = require("node:child_process");

const pkg = require("../package.json");
const {
  artifactName,
  detectLibcFromRuntime,
  detectPlatformKey,
  targetTripleForPlatformKey,
  assetPatternForPlatformKey,
  UnsupportedPlatformError
} = require("../lib/platform");
const { checkForUpdateOnce } = require("../lib/update_check");

function isDoctorCommand(argv) {
  const sub = argv[0];
  return sub === "doctor" || sub === "diagnostics";
}

function printLines(lines, { stderr } = {}) {
  for (const line of lines) {
    if (!line) continue;
    if (stderr) console.error(line);
    else console.log(line);
  }
}

function envBool(value) {
  if (!value) return false;
  const normalized = String(value).trim().toLowerCase();
  return ["1", "true", "t", "yes", "y", "on"].includes(normalized);
}

function readInstallMetadata({ fsModule, pathModule, basePath }) {
  if (!fsModule || typeof fsModule.readFileSync !== "function") return null;
  const metadataPath = pathModule.join(basePath, "docdexd-install.json");
  try {
    const raw = fsModule.readFileSync(metadataPath, "utf8");
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function formatInstallSource(meta) {
  const source = meta?.archive?.source;
  if (!source || typeof source !== "string") return "unknown";
  if (source === "local") return "local binary";
  return `release (${source})`;
}

function runDoctor() {
  const platform = process.platform;
  const arch = process.arch;

  let libc = null;
  if (platform === "linux") {
    try {
      libc = detectLibcFromRuntime();
    } catch (err) {
      printLines(
        [
          "[docdex] doctor failed: could not detect libc",
          `[docdex] Detected platform: ${platform}/${arch}`,
          `[docdex] Error: ${err?.message || String(err)}`
        ],
        { stderr: true }
      );
      process.exit(1);
      return;
    }
  }

  let report;
  try {
    const platformKey = detectPlatformKey();
    const targetTriple = targetTripleForPlatformKey(platformKey);
    const expectedAssetName = artifactName(platformKey);
    const expectedAssetPattern = assetPatternForPlatformKey(platformKey, { exampleAssetName: expectedAssetName });
    const basePath = path.join(__dirname, "..", "dist", platformKey);
    const installMeta = readInstallMetadata({ fsModule: fs, pathModule: path, basePath });
    const installSource = formatInstallSource(installMeta);

    report = {
      exitCode: 0,
      stderr: false,
      lines: [
        "[docdex] doctor",
        `[docdex] Detected platform: ${platform}/${arch}${libc ? `/${libc}` : ""}`,
        "[docdex] Supported: yes",
        `[docdex] Platform key: ${platformKey}`,
        `[docdex] Expected target triple: ${targetTriple}`,
        `[docdex] Expected release asset: ${expectedAssetName}`,
        `[docdex] Asset naming pattern: ${expectedAssetPattern}`,
        `[docdex] Install source: ${installSource}`
      ]
    };
  } catch (err) {
    if (err instanceof UnsupportedPlatformError) {
      const detected = `${err.details?.platform ?? platform}/${err.details?.arch ?? arch}`;
      const libcSuffix = err.details?.libc ? `/${err.details.libc}` : "";
      const candidatePlatformKey =
        typeof err.details?.candidatePlatformKey === "string" ? err.details.candidatePlatformKey : null;
      const candidateTargetTriple =
        typeof err.details?.candidateTargetTriple === "string" ? err.details.candidateTargetTriple : null;
      const supportedKeys = Array.isArray(err.details?.supportedPlatformKeys) ? err.details.supportedPlatformKeys : [];

      const candidateAssetName = candidatePlatformKey ? artifactName(candidatePlatformKey) : null;
      const candidateAssetPattern = candidatePlatformKey
        ? assetPatternForPlatformKey(candidatePlatformKey, { exampleAssetName: candidateAssetName })
        : null;

      report = {
        exitCode: err.exitCode || 3,
        stderr: true,
        lines: [
          "[docdex] doctor",
          `[docdex] Detected platform: ${detected}${libcSuffix}`,
          "[docdex] Supported: no",
          `[docdex] error code: ${err.code}`,
          "[docdex] No download/install is attempted for this platform.",
          candidatePlatformKey ? `[docdex] Platform key: ${candidatePlatformKey}` : null,
          candidateTargetTriple ? `[docdex] Target triple: ${candidateTargetTriple}` : null,
          candidateAssetPattern ? `[docdex] Asset naming pattern: ${candidateAssetPattern}` : null,
          supportedKeys.length ? `[docdex] Supported platforms: ${supportedKeys.join(", ")}` : null,
          "[docdex] Next steps: use a supported platform or build from source (Rust)."
        ]
      };
    } else {
      report = {
        exitCode: 1,
        stderr: true,
        lines: [
          "[docdex] doctor failed: unexpected error",
          `[docdex] Detected platform: ${platform}/${arch}${libc ? `/${libc}` : ""}`,
          `[docdex] Error: ${err?.message || String(err)}`
        ]
      };
    }
  }

  printLines(report.lines, { stderr: report.stderr });
  process.exit(report.exitCode);
}

async function run() {
  const argv = process.argv.slice(2);
  if (isDoctorCommand(argv)) {
    runDoctor();
    return;
  }

  let platformKey;
  try {
    platformKey = detectPlatformKey();
  } catch (err) {
    if (err instanceof UnsupportedPlatformError) {
      const detected = `${err.details?.platform ?? process.platform}/${err.details?.arch ?? process.arch}`;
      const libc = err.details?.libc ? `/${err.details.libc}` : "";
      console.error(`[docdex] unsupported platform (${detected}${libc})`);
      console.error(`[docdex] error code: ${err.code}`);
      console.error("[docdex] No download/run was attempted for this platform.");
      if (Array.isArray(err.details?.supportedPlatformKeys) && err.details.supportedPlatformKeys.length) {
        console.error(`[docdex] Supported platforms: ${err.details.supportedPlatformKeys.join(", ")}`);
      }
      if (typeof err.details?.candidatePlatformKey === "string") {
        console.error(`[docdex] Asset naming pattern: ${assetPatternForPlatformKey(err.details.candidatePlatformKey)}`);
      }
      console.error("[docdex] Next steps: use a supported platform or build from source (Rust).");
      process.exit(err.exitCode || 3);
      return;
    }
    console.error(`[docdex] failed to detect platform: ${err?.message || String(err)}`);
    process.exit(1);
    return;
  }

  const basePath = path.join(__dirname, "..", "dist", platformKey);
  const binaryPath = path.join(
    basePath,
    process.platform === "win32" ? "docdexd.exe" : "docdexd"
  );

  if (!fs.existsSync(binaryPath)) {
    console.error(`[docdex] Missing binary for ${platformKey}. Try reinstalling or set DOCDEX_DOWNLOAD_REPO to a repo with release assets.`);
    try {
      console.error(`[docdex] Expected target triple: ${targetTripleForPlatformKey(platformKey)}`);
      console.error(`[docdex] Asset naming pattern: ${assetPatternForPlatformKey(platformKey)}`);
    } catch {}
    process.exit(1);
    return;
  }

  await checkForUpdateOnce({
    currentVersion: pkg.version,
    env: process.env,
    stdout: process.stdout,
    stderr: process.stderr,
    logger: console
  });

  const env = { ...process.env };
  const child = spawn(binaryPath, process.argv.slice(2), { stdio: "inherit", env });
  child.on("exit", (code) => process.exit(code ?? 1));
  child.on("error", (err) => {
    console.error(`[docdex] failed to launch binary: ${err.message}`);
    process.exit(1);
  });
}

run().catch((err) => {
  console.error(`[docdex] unexpected error: ${err?.message || String(err)}`);
  process.exit(1);
});
