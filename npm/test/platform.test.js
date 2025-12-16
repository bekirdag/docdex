"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  detectLibcFromRuntime,
  detectPlatformKey,
  detectTargetTriple,
  targetTripleForPlatformKey,
  UnsupportedPlatformError
} = require("../lib/platform");

const { PUBLISHED_RELEASE_TARGETS } = require("../lib/platform_matrix");
const { DEFAULT_TARGETS } = require("../../scripts/generate_release_manifest.cjs");

function writeElf64WithInterpreter(filePath, interpreter) {
  const interpBytes = Buffer.from(`${interpreter}\0`, "utf8");
  const interpOffset = 0x100;
  const fileSize = interpOffset + interpBytes.length;
  const buf = Buffer.alloc(fileSize);

  // ELF ident
  buf[0] = 0x7f;
  buf[1] = 0x45; // E
  buf[2] = 0x4c; // L
  buf[3] = 0x46; // F
  buf[4] = 2; // 64-bit
  buf[5] = 1; // little-endian
  buf[6] = 1; // version

  // Program header table metadata (ELF64)
  const phoff = 64;
  const phentsize = 56;
  const phnum = 1;
  buf.writeBigUInt64LE(BigInt(phoff), 32);
  buf.writeUInt16LE(phentsize, 54);
  buf.writeUInt16LE(phnum, 56);

  // Single PT_INTERP program header (ELF64)
  const pBase = phoff;
  buf.writeUInt32LE(3, pBase + 0); // p_type = PT_INTERP
  buf.writeUInt32LE(4, pBase + 4); // p_flags = PF_R
  buf.writeBigUInt64LE(BigInt(interpOffset), pBase + 8); // p_offset
  buf.writeBigUInt64LE(BigInt(interpBytes.length), pBase + 32); // p_filesz
  buf.writeBigUInt64LE(BigInt(interpBytes.length), pBase + 40); // p_memsz
  buf.writeBigUInt64LE(1n, pBase + 48); // p_align

  interpBytes.copy(buf, interpOffset);
  fs.writeFileSync(filePath, buf);
}

function fsProxyNoAlpineHint() {
  return {
    openSync: fs.openSync.bind(fs),
    readSync: fs.readSync.bind(fs),
    closeSync: fs.closeSync.bind(fs),
    existsSync: (p) => (p === "/etc/alpine-release" ? false : fs.existsSync(p))
  };
}

test("targetTripleForPlatformKey maps known platform keys deterministically", () => {
  assert.equal(targetTripleForPlatformKey("darwin-arm64"), "aarch64-apple-darwin");
  assert.equal(targetTripleForPlatformKey("darwin-x64"), "x86_64-apple-darwin");
  assert.equal(targetTripleForPlatformKey("linux-x64-gnu"), "x86_64-unknown-linux-gnu");
  assert.equal(targetTripleForPlatformKey("linux-x64-musl"), "x86_64-unknown-linux-musl");
  assert.equal(targetTripleForPlatformKey("linux-arm64-gnu"), "aarch64-unknown-linux-gnu");
  assert.equal(targetTripleForPlatformKey("linux-arm64-musl"), "aarch64-unknown-linux-musl");
  assert.equal(targetTripleForPlatformKey("win32-x64"), "x86_64-pc-windows-msvc");
  assert.equal(targetTripleForPlatformKey("win32-arm64"), "aarch64-pc-windows-msvc");
});

test("detectTargetTriple deterministically maps supported runtimes", () => {
  assert.equal(detectTargetTriple({ platform: "darwin", arch: "arm64" }), "aarch64-apple-darwin");
  assert.equal(detectTargetTriple({ platform: "darwin", arch: "x64" }), "x86_64-apple-darwin");
  assert.equal(
    detectTargetTriple({ platform: "linux", arch: "x64", env: { DOCDEX_LIBC: "gnu" } }),
    "x86_64-unknown-linux-gnu"
  );
  assert.equal(
    detectTargetTriple({ platform: "linux", arch: "arm64", env: { DOCDEX_LIBC: "gnu" } }),
    "aarch64-unknown-linux-gnu"
  );
  assert.equal(detectTargetTriple({ platform: "win32", arch: "x64" }), "x86_64-pc-windows-msvc");
});

test("unpublished targets are treated as unsupported (no download expected)", () => {
  assert.throws(
    () => detectPlatformKey({ platform: "linux", arch: "arm64", env: { DOCDEX_LIBC: "musl" } }),
    (err) => {
      assert.ok(err instanceof UnsupportedPlatformError);
      assert.equal(err.code, "DOCDEX_UNSUPPORTED_PLATFORM");
      assert.equal(err.details.platform, "linux");
      assert.equal(err.details.arch, "arm64");
      assert.equal(err.details.libc, "musl");
      assert.equal(err.details.candidatePlatformKey, "linux-arm64-musl");
      assert.equal(err.details.candidateTargetTriple, "aarch64-unknown-linux-musl");
      assert.equal(err.details.reason, "target_not_published");
      return true;
    }
  );

  assert.throws(
    () => detectPlatformKey({ platform: "win32", arch: "arm64" }),
    (err) => {
      assert.ok(err instanceof UnsupportedPlatformError);
      assert.equal(err.code, "DOCDEX_UNSUPPORTED_PLATFORM");
      assert.equal(err.details.platform, "win32");
      assert.equal(err.details.arch, "arm64");
      assert.equal(err.details.candidatePlatformKey, "win32-arm64");
      assert.equal(err.details.candidateTargetTriple, "aarch64-pc-windows-msvc");
      assert.equal(err.details.reason, "target_not_published");
      return true;
    }
  );
});

test("published platform keys match manifest generator defaults", () => {
  assert.deepEqual(DEFAULT_TARGETS, PUBLISHED_RELEASE_TARGETS);
});

test("DOCDEX_LIBC invalid value fails with actionable error", () => {
  assert.throws(
    () => detectLibcFromRuntime({ env: { DOCDEX_LIBC: "nope" } }),
    /Invalid DOCDEX_LIBC=nope; expected "gnu", "musl", or "glibc"/
  );
});

test("Linux libc detection can use ELF interpreter deterministically", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-platform-test-"));
  const muslPath = path.join(tmpDir, "node-musl");
  const gnuPath = path.join(tmpDir, "node-gnu");

  writeElf64WithInterpreter(muslPath, "/lib/ld-musl-x86_64.so.1");
  writeElf64WithInterpreter(gnuPath, "/lib64/ld-linux-x86-64.so.2");

  const fsProxy = fsProxyNoAlpineHint();

  assert.equal(
    detectLibcFromRuntime({ env: {}, report: null, execPath: muslPath, fs: fsProxy }),
    "musl"
  );
  assert.equal(
    detectLibcFromRuntime({ env: {}, report: null, execPath: gnuPath, fs: fsProxy }),
    "gnu"
  );
});

test("unsupported OS/arch throws typed error with detected platform details", () => {
  assert.throws(
    () => detectPlatformKey({ platform: "freebsd", arch: "x64" }),
    (err) => {
      assert.ok(err instanceof UnsupportedPlatformError);
      assert.equal(err.code, "DOCDEX_UNSUPPORTED_PLATFORM");
      assert.equal(err.details.platform, "freebsd");
      assert.equal(err.details.arch, "x64");
      assert.ok(Array.isArray(err.details.supportedPlatformKeys));
      assert.ok(Array.isArray(err.details.supportedTargetTriples));
      return true;
    }
  );
});
