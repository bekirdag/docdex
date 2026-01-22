"use strict";

const http = require("node:http");
const https = require("node:https");
const { spawn } = require("node:child_process");
const { runBridge } = require("../npm/lib/mcp_stdio_bridge");

const DEFAULT_HTTP_BASE_URL = "http://127.0.0.1:28491";
const DEFAULT_LOG_LEVEL = "warn";
const HEALTH_PATH = "/healthz";

function parseArgs(argv) {
  const parsed = {
    repoPath: ".",
    httpBaseUrl: DEFAULT_HTTP_BASE_URL,
    mcpTransport: "",
    mcpSocketPath: "",
    mcpPipeName: "",
    docdexdBin: "docdexd",
    logLevel: DEFAULT_LOG_LEVEL
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    switch (arg) {
      case "--repo":
      case "--repo-path":
        parsed.repoPath = argv[i + 1] || parsed.repoPath;
        i += 1;
        break;
      case "--http-base-url":
        parsed.httpBaseUrl = argv[i + 1] || parsed.httpBaseUrl;
        i += 1;
        break;
      case "--mcp-transport":
        parsed.mcpTransport = argv[i + 1] || parsed.mcpTransport;
        i += 1;
        break;
      case "--mcp-socket-path":
        parsed.mcpSocketPath = argv[i + 1] || parsed.mcpSocketPath;
        i += 1;
        break;
      case "--mcp-pipe-name":
        parsed.mcpPipeName = argv[i + 1] || parsed.mcpPipeName;
        i += 1;
        break;
      case "--docdexd-bin":
        parsed.docdexdBin = argv[i + 1] || parsed.docdexdBin;
        i += 1;
        break;
      case "--log-level":
        parsed.logLevel = argv[i + 1] || parsed.logLevel;
        i += 1;
        break;
      default:
        break;
    }
  }

  return parsed;
}

function parseBaseUrl(baseUrl) {
  let url;
  try {
    url = new URL(baseUrl);
  } catch (err) {
    throw new Error(`invalid http base url: ${baseUrl}`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error(`unsupported protocol for http base url: ${baseUrl}`);
  }
  const port = url.port ? Number(url.port) : 28491;
  const host = url.hostname || "127.0.0.1";
  return { url, host, port };
}

function requestHealth(url) {
  const client = url.protocol === "https:" ? https : http;
  return new Promise((resolve) => {
    const req = client.request(
      {
        method: "GET",
        hostname: url.hostname,
        port: url.port || (url.protocol === "https:" ? 443 : 80),
        path: url.pathname
      },
      (res) => {
        res.resume();
        resolve(res.statusCode && res.statusCode >= 200 && res.statusCode < 300);
      }
    );
    req.on("error", () => resolve(false));
    req.end();
  });
}

async function waitForHealth(healthUrl, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await requestHealth(healthUrl)) {
      return true;
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  return false;
}

function pipeChildToStderr(child) {
  if (child.stdout) {
    child.stdout.on("data", (chunk) => process.stderr.write(chunk));
  }
  if (child.stderr) {
    child.stderr.on("data", (chunk) => process.stderr.write(chunk));
  }
}

function spawnDocdexd(options) {
  const args = [
    "serve",
    "--repo",
    options.repoPath,
    "--enable-mcp",
    "--log",
    options.logLevel,
    "--host",
    options.host,
    "--port",
    String(options.port)
  ];

  if (options.mcpTransport === "ipc" || options.mcpSocketPath || options.mcpPipeName) {
    args.push("--mcp-ipc", "auto");
    if (options.mcpSocketPath) {
      args.push("--mcp-socket-path", options.mcpSocketPath);
    }
    if (options.mcpPipeName) {
      args.push("--mcp-pipe-name", options.mcpPipeName);
    }
  }

  return spawn(options.docdexdBin, args, { stdio: ["ignore", "pipe", "pipe"] });
}

async function ensureDocdexd(options) {
  const healthUrl = new URL(HEALTH_PATH, options.httpBaseUrl);
  if (await requestHealth(healthUrl)) {
    return null;
  }

  const child = spawnDocdexd(options);
  pipeChildToStderr(child);

  const healthy = await waitForHealth(healthUrl, 15000);
  if (!healthy) {
    child.kill("SIGTERM");
    throw new Error("docdexd did not become healthy within 15s");
  }

  return child;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const base = parseBaseUrl(args.httpBaseUrl);

  if (args.mcpTransport) {
    process.env.DOCDEX_MCP_TRANSPORT = args.mcpTransport;
  }
  if (args.mcpSocketPath) {
    process.env.DOCDEX_MCP_SOCKET_PATH = args.mcpSocketPath;
  }
  if (args.mcpPipeName) {
    process.env.DOCDEX_MCP_PIPE_NAME = args.mcpPipeName;
  }
  process.env.DOCDEX_HTTP_BASE_URL = base.url.toString().replace(/\/$/, "");

  let child = null;
  let exiting = false;
  try {
    child = await ensureDocdexd({
      repoPath: args.repoPath,
      httpBaseUrl: base.url,
      host: base.host,
      port: base.port,
      mcpTransport: args.mcpTransport,
      mcpSocketPath: args.mcpSocketPath,
      mcpPipeName: args.mcpPipeName,
      docdexdBin: args.docdexdBin,
      logLevel: args.logLevel
    });
  } catch (err) {
    process.stderr.write(`[docdex-smithery] failed to start docdexd: ${err}\n`);
    process.exit(1);
    return;
  }

  const exitChild = () => {
    if (exiting) return;
    exiting = true;
    if (child) {
      child.kill("SIGTERM");
    }
  };

  process.on("SIGINT", () => {
    exitChild();
    process.exit(130);
  });
  process.on("SIGTERM", () => {
    exitChild();
    process.exit(143);
  });
  process.on("exit", exitChild);

  if (child) {
    child.on("exit", (code) => {
      if (exiting) return;
      process.stderr.write(`[docdex-smithery] docdexd exited (${code ?? 1})\n`);
      process.exit(code ?? 1);
    });
    child.on("error", (err) => {
      if (exiting) return;
      process.stderr.write(`[docdex-smithery] docdexd error: ${err}\n`);
      process.exit(1);
    });
  }

  await runBridge({
    stdin: process.stdin,
    stdout: process.stdout,
    stderr: process.stderr
  });
}

main().catch((err) => {
  process.stderr.write(`[docdex-smithery] fatal: ${err}\n`);
  process.exit(1);
});
