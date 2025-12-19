#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");

const { recoverInterruptedInstallSync } = require("../lib/install");
const {
  artifactName,
  detectLibcFromRuntime,
  detectPlatformKey,
  targetTripleForPlatformKey,
  assetPatternForPlatformKey,
  UnsupportedPlatformError
} = require("../lib/platform");

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

function ensureExecutable(binaryPath, fsModule = fs) {
  if (process.platform === "win32") return true;
  if (typeof fsModule?.accessSync !== "function") return true;
  const xOk = fsModule?.constants?.X_OK;
  if (typeof xOk !== "number") return true;

  try {
    fsModule.accessSync(binaryPath, xOk);
    return true;
  } catch {
    if (typeof fsModule?.chmodSync === "function") {
      try {
        fsModule.chmodSync(binaryPath, 0o755);
        fsModule.accessSync(binaryPath, xOk);
        return true;
      } catch {}
    }
  }

  console.error(`[docdex] Binary is not executable: ${binaryPath}`);
  return false;
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
        `[docdex] Asset naming pattern: ${expectedAssetPattern}`
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

function run() {
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
    }
    console.error(`[docdex] failed to detect platform: ${err?.message || String(err)}`);
    process.exit(1);
  }

<<<<<<< HEAD
  const env = process.env || {};
  const stateRootDir =
    typeof env.DOCDEX_INSTALL_STATE_DIR === "string" && env.DOCDEX_INSTALL_STATE_DIR.trim()
      ? path.resolve(env.DOCDEX_INSTALL_STATE_DIR.trim())
      : path.join(os.homedir(), ".docdex", "state");

  const stateBinaryPath = path.join(
    stateRootDir,
    "daemon",
    platformKey,
=======
  const basePath = path.join(__dirname, "..", "dist", platformKey);
  try {
    recoverInterruptedInstallSync({
      fsModule: fs,
      pathModule: path,
      distDir: basePath,
      isWin32: process.platform === "win32"
    });
  } catch {}
  const binaryPath = path.join(
    basePath,
>>>>>>> mcoda/task/ops-01-us-05-t05
    process.platform === "win32" ? "docdexd.exe" : "docdexd"
  );

  const distBinaryPath = path.join(
    __dirname,
    "..",
    "dist",
    platformKey,
    process.platform === "win32" ? "docdexd.exe" : "docdexd"
  );

  const binaryPath = fs.existsSync(stateBinaryPath)
    ? stateBinaryPath
    : fs.existsSync(distBinaryPath)
      ? distBinaryPath
      : null;

  if (!binaryPath) {
    console.error(`[docdex] Missing binary for ${platformKey}. Try reinstalling or set DOCDEX_DOWNLOAD_REPO to a repo with release assets.`);
    try {
      console.error(`[docdex] Expected target triple: ${targetTripleForPlatformKey(platformKey)}`);
      console.error(`[docdex] Asset naming pattern: ${assetPatternForPlatformKey(platformKey)}`);
    } catch {}
    process.exit(1);
  }

  if (!ensureExecutable(binaryPath)) {
    process.exit(1);
  }

  const child = spawn(binaryPath, process.argv.slice(2), { stdio: "inherit" });
  child.on("exit", (code) => process.exit(code ?? 1));
  child.on("error", (err) => {
    console.error(`[docdex] failed to launch binary: ${err.message}`);
    process.exit(1);
  });
}

run();
