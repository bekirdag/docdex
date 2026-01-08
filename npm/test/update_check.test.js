"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");

const { checkForUpdate, compareSemver, parseSemver } = require("../lib/update_check");

function createHttpsMock({ statusCode = 200, body = JSON.stringify({ version: "0.2.99" }) } = {}) {
  return {
    request: (_url, _options, onResponse) => {
      const req = new EventEmitter();
      req.setTimeout = (_ms, _handler) => req;
      req.destroy = () => {};
      req.end = () => {
        const res = new EventEmitter();
        res.statusCode = statusCode;
        res.setEncoding = () => {};
        res.resume = () => {};
        if (typeof onResponse === "function") onResponse(res);
        if (body != null) res.emit("data", body);
        res.emit("end");
      };
      return req;
    }
  };
}

test("compareSemver treats prerelease lower than release", () => {
  const prerelease = parseSemver("0.2.18-beta.1");
  const release = parseSemver("0.2.18");
  assert.equal(compareSemver(prerelease, release), -1);
});

test("checkForUpdate logs when a newer version exists", async () => {
  const logs = [];
  const logger = { log: (line) => logs.push(line) };
  const result = await checkForUpdate({
    currentVersion: "0.2.18",
    env: { DOCDEX_UPDATE_CHECK: "1" },
    stdout: { isTTY: true },
    stderr: { isTTY: true },
    httpsModule: createHttpsMock({ body: JSON.stringify({ version: "0.2.21" }) }),
    logger
  });

  assert.equal(result.updateAvailable, true);
  assert.ok(logs.some((line) => line.includes("Update available")));
});

test("checkForUpdate skips when disabled", async () => {
  let called = false;
  const httpsModule = {
    request: () => {
      called = true;
      return new EventEmitter();
    }
  };

  const result = await checkForUpdate({
    currentVersion: "0.2.18",
    env: { DOCDEX_UPDATE_CHECK: "0" },
    stdout: { isTTY: true },
    stderr: { isTTY: true },
    httpsModule
  });

  assert.equal(result.checked, false);
  assert.equal(called, false);
});
