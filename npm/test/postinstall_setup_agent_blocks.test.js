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

test("applyAgentInstructions updates continue yaml rules in place", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-continue-yaml-agents-"));
  const prev = {
    HOME: process.env.HOME,
    USERPROFILE: process.env.USERPROFILE,
    APPDATA: process.env.APPDATA
  };
  process.env.HOME = dir;
  process.env.USERPROFILE = dir;
  process.env.APPDATA = path.join(dir, "AppData", "Roaming");
  try {
    const target = path.join(dir, ".continue", "config.yaml");
    const oldBlock = [
      "---- START OF DOCDEX INFO V0.2.17 ----",
      "OLD DOCDEX INSTRUCTIONS",
      "---- END OF DOCDEX INFO ----"
    ]
      .map((line) => `    ${line}`)
      .join("\n");
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(
      target,
      [
        "name: test-config",
        "rules:",
        "  - Always keep this line",
        "  - |",
        oldBlock,
        "  - Keep this too"
      ].join("\n")
    );
    const result = applyAgentInstructions({ logger: { warn: () => {} } });
    assert.equal(result.ok, true);
    const contents = fs.readFileSync(target, "utf8");
    assert.ok(contents.includes("rules:"));
    assert.ok(contents.includes("Always keep this line"));
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

test("applyAgentInstructions writes Claude Code instructions file", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-claude-code-agents-"));
  const prev = {
    HOME: process.env.HOME,
    USERPROFILE: process.env.USERPROFILE,
    APPDATA: process.env.APPDATA
  };
  process.env.HOME = dir;
  process.env.USERPROFILE = dir;
  process.env.APPDATA = path.join(dir, "AppData", "Roaming");
  try {
    const target = path.join(dir, ".claude", "CLAUDE.md");
    const result = applyAgentInstructions({ logger: { warn: () => {} } });
    assert.equal(result.ok, true);
    const contents = fs.readFileSync(target, "utf8");
    const startMarker = `---- START OF DOCDEX INFO V${PACKAGE_VERSION} ----`;
    assert.ok(contents.includes(startMarker));
    assert.ok(contents.includes("---- END OF DOCDEX INFO -----"));
  } finally {
    process.env.HOME = prev.HOME;
    process.env.USERPROFILE = prev.USERPROFILE;
    process.env.APPDATA = prev.APPDATA;
  }
});

test("applyAgentInstructions writes Gemini instructions file", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-gemini-agents-"));
  const prev = {
    HOME: process.env.HOME,
    USERPROFILE: process.env.USERPROFILE,
    APPDATA: process.env.APPDATA
  };
  process.env.HOME = dir;
  process.env.USERPROFILE = dir;
  process.env.APPDATA = path.join(dir, "AppData", "Roaming");
  try {
    const target = path.join(dir, ".gemini", "GEMINI.md");
    const result = applyAgentInstructions({ logger: { warn: () => {} } });
    assert.equal(result.ok, true);
    const contents = fs.readFileSync(target, "utf8");
    const startMarker = `---- START OF DOCDEX INFO V${PACKAGE_VERSION} ----`;
    assert.ok(contents.includes(startMarker));
    assert.ok(contents.includes("---- END OF DOCDEX INFO -----"));
  } finally {
    process.env.HOME = prev.HOME;
    process.env.USERPROFILE = prev.USERPROFILE;
    process.env.APPDATA = prev.APPDATA;
  }
});

test("applyAgentInstructions writes VS Code chat instructions setting", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-vscode-agents-"));
  const prev = {
    HOME: process.env.HOME,
    USERPROFILE: process.env.USERPROFILE,
    APPDATA: process.env.APPDATA
  };
  process.env.HOME = dir;
  process.env.USERPROFILE = dir;
  process.env.APPDATA = path.join(dir, "AppData", "Roaming");
  const settingsPath =
    process.platform === "win32"
      ? path.join(dir, "AppData", "Roaming", "Code", "User", "settings.json")
      : process.platform === "darwin"
        ? path.join(dir, "Library", "Application Support", "Code", "User", "settings.json")
        : path.join(dir, ".config", "Code", "User", "settings.json");
  try {
    const globalInstructions = path.join(dir, ".vscode", "global_instructions.md");
    const instructionsFile = path.join(dir, ".vscode", "instructions", "docdex.md");
    const result = applyAgentInstructions({ logger: { warn: () => {} } });
    assert.equal(result.ok, true);
    const settings = JSON.parse(fs.readFileSync(settingsPath, "utf8"));
    const startMarker = `---- START OF DOCDEX INFO V${PACKAGE_VERSION} ----`;
    const instructions = settings["chat.instructions"];
    assert.equal(typeof instructions, "string");
    assert.ok(instructions.includes(startMarker));
    assert.ok(instructions.includes("---- END OF DOCDEX INFO -----"));
    assert.equal(settings["github.copilot.chat.codeGeneration.instructions"], undefined);
    assert.equal(settings["copilot.chat.codeGeneration.instructions"], undefined);
    assert.equal(settings["chat.instructionsFilesLocations"], undefined);
    assert.equal(fs.existsSync(globalInstructions), false);
    assert.equal(fs.existsSync(instructionsFile), false);
  } finally {
    process.env.HOME = prev.HOME;
    process.env.USERPROFILE = prev.USERPROFILE;
    process.env.APPDATA = prev.APPDATA;
  }
});

test("applyAgentInstructions cleans legacy Cursor agents files", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-cursor-agents-"));
  const prev = {
    HOME: process.env.HOME,
    USERPROFILE: process.env.USERPROFILE,
    APPDATA: process.env.APPDATA
  };
  process.env.HOME = dir;
  process.env.USERPROFILE = dir;
  process.env.APPDATA = path.join(dir, "AppData", "Roaming");
  try {
    const lowerPath = path.join(dir, ".cursor", "agents.md");
    const upperPath = path.join(dir, ".cursor", "AGENTS.md");
    const legacyBlock = [
      "---- START OF DOCDEX INFO V0.2.17 ----",
      "LEGACY DOCDEX INSTRUCTIONS",
      "---- END OF DOCDEX INFO -----"
    ].join("\n");
    fs.mkdirSync(path.dirname(lowerPath), { recursive: true });
    fs.writeFileSync(lowerPath, legacyBlock);
    fs.writeFileSync(upperPath, legacyBlock);
    const result = applyAgentInstructions({ logger: { warn: () => {} } });
    assert.equal(result.ok, true);
    assert.equal(fs.existsSync(lowerPath), false);
    assert.equal(fs.existsSync(upperPath), false);
  } finally {
    process.env.HOME = prev.HOME;
    process.env.USERPROFILE = prev.USERPROFILE;
    process.env.APPDATA = prev.APPDATA;
  }
});
