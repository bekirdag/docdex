const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { version: PACKAGE_VERSION } = require("../package.json");

const { applyAgentInstructions } = require("../lib/postinstall_setup");

test("applyAgentInstructions removes legacy unmarked docdex block", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-codex-agents-legacy-"));
  const prev = {
    HOME: process.env.HOME,
    USERPROFILE: process.env.USERPROFILE,
    APPDATA: process.env.APPDATA
  };
  process.env.HOME = dir;
  process.env.USERPROFILE = dir;
  process.env.APPDATA = path.join(dir, "AppData", "Roaming");
  try {
    const target = path.join(dir, ".codex", "AGENTS.md");
    const legacy = fs.readFileSync(path.join(__dirname, "..", "assets", "agents.md"), "utf8").trim();
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, `Some other rules\n\n${legacy}\n\n# Other Rules\nKeep this line\n`);
    const result = applyAgentInstructions({ logger: { warn: () => {} } });
    assert.equal(result.ok, true);
    const contents = fs.readFileSync(target, "utf8");
    const startMarker = `---- START OF DOCDEX INFO V${PACKAGE_VERSION} ----`;
    assert.ok(contents.includes(startMarker));
    assert.ok(contents.includes("---- END OF DOCDEX INFO -----"));
    assert.ok(contents.includes("Some other rules"));
    assert.ok(contents.includes("Keep this line"));
    const parts = contents.split(startMarker);
    assert.equal(parts.length - 1, 1);
    const remainder = parts[1].split("---- END OF DOCDEX INFO -----")[1] || "";
    assert.ok(!parts[0].includes("# Docdex Agent Usage Instructions"));
    assert.ok(!remainder.includes("# Docdex Agent Usage Instructions"));
  } finally {
    process.env.HOME = prev.HOME;
    process.env.USERPROFILE = prev.USERPROFILE;
    process.env.APPDATA = prev.APPDATA;
  }
});

test("applyAgentInstructions updates yaml instructions in place", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-yaml-agents-"));
  const prev = {
    HOME: process.env.HOME,
    USERPROFILE: process.env.USERPROFILE,
    APPDATA: process.env.APPDATA
  };
  process.env.HOME = dir;
  process.env.USERPROFILE = dir;
  process.env.APPDATA = path.join(dir, "AppData", "Roaming");
  try {
    const target = path.join(dir, ".aider.conf.yml");
    const oldBlock = [
      "---- START OF DOCDEX INFO V0.2.17 ----",
      "OLD DOCDEX INSTRUCTIONS",
      "---- END OF DOCDEX INFO -----"
    ]
      .map((line) => `  ${line}`)
      .join("\n");
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, `system-prompt: |\n  Keep this line\n${oldBlock}\n  Keep this too\n`);
    const result = applyAgentInstructions({ logger: { warn: () => {} } });
    assert.equal(result.ok, true);
    const contents = fs.readFileSync(target, "utf8");
    assert.ok(contents.includes("system-prompt: |"));
    assert.ok(contents.includes("Keep this line"));
    assert.ok(contents.includes("Keep this too"));
    assert.ok(contents.includes(`---- START OF DOCDEX INFO V${PACKAGE_VERSION} ----`));
    assert.ok(contents.includes("---- END OF DOCDEX INFO -----"));
    assert.ok(!contents.includes("V0.2.17"));
  } finally {
    process.env.HOME = prev.HOME;
    process.env.USERPROFILE = prev.USERPROFILE;
    process.env.APPDATA = prev.APPDATA;
  }
});
