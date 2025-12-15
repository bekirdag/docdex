"use strict";

function detectLibc() {
  const override = process.env.DOCDEX_LIBC;
  if (override) {
    const libc = override.toLowerCase();
    if (libc === "musl" || libc === "gnu") {
      return libc;
    }
  }

  const report = typeof process.report?.getReport === "function" ? process.report.getReport() : null;
  const glibcVersion = report?.header?.glibcVersionRuntime;
  return glibcVersion ? "gnu" : "musl";
}

function detectPlatformKey() {
  const platform = process.platform;
  const arch = process.arch;

  if (platform === "darwin") {
    if (arch === "arm64") return "darwin-arm64";
    if (arch === "x64") return "darwin-x64";
  }

  if (platform === "linux") {
    const libc = detectLibc();
    if (arch === "arm64") return `linux-arm64-${libc}`;
    if (arch === "x64") return `linux-x64-${libc}`;
  }

  if (platform === "win32") {
    if (arch === "x64") return "win32-x64";
    if (arch === "arm64") return "win32-arm64";
  }

  throw new Error(`Unsupported platform: ${platform}/${arch}`);
}

function artifactName(platformKey) {
  return `docdexd-${platformKey}.tar.gz`;
}

function targetTripleForPlatformKey(platformKey) {
  switch (platformKey) {
    case "darwin-arm64":
      return "aarch64-apple-darwin";
    case "darwin-x64":
      return "x86_64-apple-darwin";
    case "linux-x64-gnu":
      return "x86_64-unknown-linux-gnu";
    case "linux-x64-musl":
      return "x86_64-unknown-linux-musl";
    case "linux-arm64-gnu":
      return "aarch64-unknown-linux-gnu";
    case "linux-arm64-musl":
      return "aarch64-unknown-linux-musl";
    case "win32-x64":
      return "x86_64-pc-windows-msvc";
    case "win32-arm64":
      return "aarch64-pc-windows-msvc";
    default:
      throw new Error(`Unsupported platform key: ${platformKey}`);
  }
}

function detectTargetTriple() {
  return targetTripleForPlatformKey(detectPlatformKey());
}

module.exports = {
  detectLibc,
  detectPlatformKey,
  artifactName,
  targetTripleForPlatformKey,
  detectTargetTriple
};
