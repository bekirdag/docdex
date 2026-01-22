const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const { PassThrough } = require("node:stream");
const path = require("node:path");
const os = require("node:os");
const fs = require("node:fs");
const { runBridge } = require("../lib/mcp_stdio_bridge");

function withEnv(vars, fn) {
  const original = {};
  for (const [key, value] of Object.entries(vars)) {
    original[key] = process.env[key];
    if (value === null) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
  return Promise.resolve()
    .then(fn)
    .finally(() => {
      for (const [key, value] of Object.entries(original)) {
        if (value === undefined) {
          delete process.env[key];
        } else {
          process.env[key] = value;
        }
      }
    });
}

function startServer(handler) {
  return new Promise((resolve, reject) => {
    const server = http.createServer(handler);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        reject(new Error("failed to bind test server"));
        return;
      }
      resolve({
        baseUrl: `http://127.0.0.1:${address.port}`,
        close: () => new Promise((res) => server.close(() => res()))
      });
    });
  });
}

async function runBridgeWithInput(input) {
  const stdin = new PassThrough();
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  let out = "";
  let err = "";
  stdout.on("data", (chunk) => {
    out += chunk.toString("utf8");
  });
  stderr.on("data", (chunk) => {
    err += chunk.toString("utf8");
  });
  const bridgePromise = runBridge({ stdin, stdout, stderr });
  stdin.write(input);
  stdin.end();
  await bridgePromise;
  return { out, err };
}

async function startUnixSocketServer(handler) {
  const socketPath = path.join(os.tmpdir(), `docdex-mcp-${Date.now()}-${Math.random()}.sock`);
  return new Promise((resolve, reject) => {
    const server = http.createServer(handler);
    server.listen(socketPath, () => {
      resolve({
        socketPath,
        close: () =>
          new Promise((res) =>
            server.close(() => {
              fs.rmSync(socketPath, { force: true });
              res();
            })
          )
      });
    });
    server.on("error", reject);
  });
}

test("stdio bridge forwards JSON-RPC and emits one line", async () => {
  const server = await startServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk.toString("utf8");
    });
    req.on("end", () => {
      const payload = JSON.parse(body);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: payload.id, result: "ok" }));
    });
  });

  await withEnv({ DOCDEX_HTTP_BASE_URL: server.baseUrl, DOCDEX_MCP_TRANSPORT: "http" }, async () => {
    const payload = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }) + "\n";
    const { out, err } = await runBridgeWithInput(payload);
    assert.equal(err, "");
    const lines = out.trim().split("\n");
    assert.equal(lines.length, 1);
    const response = JSON.parse(lines[0]);
    assert.equal(response.result, "ok");
    assert.equal(response.id, 1);
  });

  await server.close();
});

test("stdio bridge handles batch payloads", async () => {
  const server = await startServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk.toString("utf8");
    });
    req.on("end", () => {
      const payload = JSON.parse(body);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(payload.map((item) => ({ jsonrpc: "2.0", id: item.id, result: "ok" }))));
    });
  });

  await withEnv({ DOCDEX_HTTP_BASE_URL: server.baseUrl, DOCDEX_MCP_TRANSPORT: "http" }, async () => {
    const payload = JSON.stringify([
      { jsonrpc: "2.0", id: 1, method: "ping" },
      { jsonrpc: "2.0", id: 2, method: "ping" }
    ]) + "\n";
    const { out } = await runBridgeWithInput(payload);
    const response = JSON.parse(out.trim());
    assert.equal(Array.isArray(response), true);
    assert.equal(response.length, 2);
    assert.equal(response[0].id, 1);
  });

  await server.close();
});

test("stdio bridge emits parse error for invalid JSON", async () => {
  await withEnv({ DOCDEX_MCP_TRANSPORT: "http" }, async () => {
    const { out } = await runBridgeWithInput("{not-json}\n");
    const response = JSON.parse(out.trim());
    assert.equal(response.error.code, -32700);
  });
});

test("stdio bridge rejects invalid transport env", async () => {
  const stdin = new PassThrough();
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  await withEnv({ DOCDEX_MCP_TRANSPORT: "bad" }, async () => {
    await assert.rejects(() => runBridge({ stdin, stdout, stderr }), /invalid DOCDEX_MCP_TRANSPORT/);
  });
});

test("stdio bin emits only JSON responses", async () => {
  const server = await startServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk.toString("utf8");
    });
    req.on("end", () => {
      const payload = JSON.parse(body);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: payload.id, result: "ok" }));
    });
  });

  await withEnv({ DOCDEX_HTTP_BASE_URL: server.baseUrl, DOCDEX_MCP_TRANSPORT: "http" }, async () => {
    const { spawn } = require("node:child_process");
    const binPath = path.join(__dirname, "..", "bin", "docdex-mcp-stdio.js");
    const child = spawn(process.execPath, [binPath], {
      stdio: ["pipe", "pipe", "pipe"],
      env: process.env
    });

    let out = "";
    child.stdout.on("data", (chunk) => {
      out += chunk.toString("utf8");
    });

    const payload = JSON.stringify({ jsonrpc: "2.0", id: 7, method: "ping" }) + "\n";
    child.stdin.write(payload);
    child.stdin.end();

    await new Promise((resolve, reject) => {
      child.on("error", reject);
      child.on("close", () => resolve());
    });

    const lines = out.trim().split("\n").filter(Boolean);
    assert.equal(lines.length, 1);
    const response = JSON.parse(lines[0]);
    assert.equal(response.id, 7);
    assert.equal(response.result, "ok");
  });

  await server.close();
});

if (process.platform !== "win32") {
  test("stdio bridge supports ipc transport", async () => {
    const server = await startUnixSocketServer((req, res) => {
      let body = "";
      req.on("data", (chunk) => {
        body += chunk.toString("utf8");
      });
      req.on("end", () => {
        const payload = JSON.parse(body);
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: payload.id, result: "ipc" }));
      });
    });

    await withEnv(
      {
        DOCDEX_HTTP_BASE_URL: "http://127.0.0.1:1",
        DOCDEX_MCP_TRANSPORT: "ipc",
        DOCDEX_MCP_SOCKET_PATH: server.socketPath
      },
      async () => {
        const payload = JSON.stringify({ jsonrpc: "2.0", id: 42, method: "ping" }) + "\n";
        const { out } = await runBridgeWithInput(payload);
        const response = JSON.parse(out.trim());
        assert.equal(response.result, "ipc");
      }
    );

    await server.close();
  });

  test("stdio bridge falls back to ipc when http fails", async () => {
    const server = await startUnixSocketServer((req, res) => {
      let body = "";
      req.on("data", (chunk) => {
        body += chunk.toString("utf8");
      });
      req.on("end", () => {
        const payload = JSON.parse(body);
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: payload.id, result: "fallback" }));
      });
    });

    await withEnv(
      {
        DOCDEX_HTTP_BASE_URL: "http://127.0.0.1:1",
        DOCDEX_MCP_SOCKET_PATH: server.socketPath
      },
      async () => {
        const payload = JSON.stringify({ jsonrpc: "2.0", id: 100, method: "ping" }) + "\n";
        const { out } = await runBridgeWithInput(payload);
        const response = JSON.parse(out.trim());
        assert.equal(response.result, "fallback");
      }
    );

    await server.close();
  });
}
