"use strict";

const http = require("node:http");
const https = require("node:https");
const readline = require("node:readline");
const { URL } = require("node:url");

const DEFAULT_HTTP_BASE = "http://127.0.0.1:28491";

function trimEnv(value) {
  if (!value) return "";
  const trimmed = String(value).trim();
  return trimmed;
}

function jsonRpcError(message, id, code = -32000, data) {
  const payload = {
    jsonrpc: "2.0",
    id: typeof id === "undefined" ? null : id,
    error: {
      code,
      message
    }
  };
  if (data !== undefined) {
    payload.error.data = data;
  }
  return payload;
}

function extractIds(payload) {
  if (Array.isArray(payload)) {
    return payload
      .map((item) => (item && Object.prototype.hasOwnProperty.call(item, "id") ? item.id : undefined))
      .filter((value) => value !== undefined);
  }
  if (payload && Object.prototype.hasOwnProperty.call(payload, "id")) {
    return [payload.id];
  }
  return [];
}

function normalizePipeName(name) {
  if (!name) return "";
  if (name.startsWith("\\\\.\\pipe\\")) return name;
  return `\\\\.\\pipe\\${name}`;
}

function defaultUnixSocketPath() {
  const runtime = trimEnv(process.env.XDG_RUNTIME_DIR);
  if (runtime) {
    return `${runtime.replace(/\/$/, "")}/docdex/mcp.sock`;
  }
  const home = trimEnv(process.env.HOME);
  if (!home) return "";
  return `${home.replace(/\/$/, "")}/.docdex/run/mcp.sock`;
}

function readTransportEnv() {
  const transport = trimEnv(process.env.DOCDEX_MCP_TRANSPORT).toLowerCase();
  if (transport && transport !== "http" && transport !== "ipc") {
    throw new Error(`invalid DOCDEX_MCP_TRANSPORT: ${transport}`);
  }
  return transport;
}

function resolveIpcConfig(transport) {
  const socketPathEnv = trimEnv(process.env.DOCDEX_MCP_SOCKET_PATH);
  const pipeNameEnv = trimEnv(process.env.DOCDEX_MCP_PIPE_NAME);
  const explicitIpc = transport === "ipc" || socketPathEnv || pipeNameEnv;
  if (!explicitIpc) return null;

  if (process.platform === "win32") {
    const pipeName = normalizePipeName(pipeNameEnv || "docdex-mcp");
    return { type: "pipe", pipeName };
  }

  const socketPath = socketPathEnv || defaultUnixSocketPath();
  if (!socketPath) {
    throw new Error("DOCDEX_MCP_SOCKET_PATH not set and HOME/XDG_RUNTIME_DIR unavailable");
  }
  return { type: "unix", socketPath };
}

function resolveHttpBaseUrl() {
  const base = trimEnv(process.env.DOCDEX_HTTP_BASE_URL) || DEFAULT_HTTP_BASE;
  return base;
}

function buildHttpEndpoint(baseUrl) {
  const parsed = new URL(baseUrl);
  const endpoint = new URL("/v1/mcp", parsed);
  return endpoint;
}

function requestJson({ url, payload, socketPath }) {
  const data = JSON.stringify(payload);
  const isHttps = url.protocol === "https:";
  const requestFn = isHttps ? https.request : http.request;
  const options = {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "content-length": Buffer.byteLength(data)
    }
  };
  if (socketPath) {
    options.socketPath = socketPath;
    options.path = url.pathname;
  } else {
    options.hostname = url.hostname;
    options.port = url.port || (isHttps ? 443 : 80);
    options.path = url.pathname;
  }

  return new Promise((resolve, reject) => {
    const req = requestFn(options, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => {
        body += chunk;
      });
      res.on("end", () => {
        resolve({
          status: res.statusCode || 0,
          body
        });
      });
    });
    req.on("error", reject);
    req.write(data);
    req.end();
  });
}

async function forwardRequest(payload, stderr) {
  const transport = readTransportEnv();
  const httpBase = resolveHttpBaseUrl();
  const endpoint = buildHttpEndpoint(httpBase);
  const ipcConfig = resolveIpcConfig(transport);

  const tryHttp = async () => requestJson({ url: endpoint, payload });
  const tryIpc = async () => {
    if (!ipcConfig) {
      throw new Error("IPC transport not configured");
    }
    const ipcUrl = new URL("http://localhost/v1/mcp");
    const socketPath = ipcConfig.type === "unix" ? ipcConfig.socketPath : ipcConfig.pipeName;
    return requestJson({ url: ipcUrl, payload, socketPath });
  };

  if (transport === "ipc") {
    return await tryIpc();
  }
  if (transport === "http") {
    return await tryHttp();
  }

  try {
    return await tryHttp();
  } catch (err) {
    if (ipcConfig) {
      stderr.write(`[docdex-mcp-stdio] HTTP failed, falling back to IPC: ${err}\n`);
      return await tryIpc();
    }
    throw err;
  }
}

async function writeLine(stdout, line) {
  if (!line.endsWith("\n")) {
    line += "\n";
  }
  if (!stdout.write(line)) {
    await new Promise((resolve) => stdout.once("drain", resolve));
  }
}

async function handlePayload(payload, stdout, stderr) {
  const ids = extractIds(payload);
  let response;
  try {
    const result = await forwardRequest(payload, stderr);
    if (result.body) {
      try {
        response = JSON.parse(result.body);
      } catch (err) {
        response = jsonRpcError("invalid json response from docdex", ids[0], -32001, {
          status: result.status,
          body: result.body
        });
      }
    } else if (ids.length === 1) {
      response = { jsonrpc: "2.0", id: ids[0], result: null };
    } else if (ids.length > 1) {
      response = ids.map((id) => ({ jsonrpc: "2.0", id, result: null }));
    } else {
      response = null;
    }
  } catch (err) {
    response = jsonRpcError("transport error", ids[0], -32002, {
      error: String(err)
    });
  }
  if (response !== null) {
    await writeLine(stdout, JSON.stringify(response));
  }
}

async function runBridge({ stdin, stdout, stderr }) {
  readTransportEnv();
  const rl = readline.createInterface({
    input: stdin,
    crlfDelay: Infinity
  });

  for await (const line of rl) {
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }
    let payload;
    try {
      payload = JSON.parse(trimmed);
    } catch (err) {
      const response = jsonRpcError("parse error", null, -32700, { error: String(err) });
      await writeLine(stdout, JSON.stringify(response));
      continue;
    }
    await handlePayload(payload, stdout, stderr);
  }
}

module.exports = {
  runBridge
};
