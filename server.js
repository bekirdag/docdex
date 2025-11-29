import express from "express";
import bodyParser from "body-parser";
import { spawn } from "child_process";

const app = express();
const PORT = process.env.PORT || 8080;

// Defaults (can be overridden via config or env)
const DEFAULT_REPO = process.env.DOCDEX_REPO_PATH || "/source";
const DEFAULT_LOG = process.env.DOCDEX_LOG_LEVEL || "warn";
const DEFAULT_MAX_RESULTS = Number(process.env.DOCDEX_MAX_RESULTS || 8);

// Parse JSON bodies
app.use(bodyParser.json());

// ---------------------------------------------------------------------------
// Serve .well-known (server card + icon)
// ---------------------------------------------------------------------------

// Smithery will hit e.g.:
//   https://server.smithery.ai/@bekirdag/docdex/.well-known/mcp/server-card.json
// The repo is copied to /source, so we serve /source/.well-known.
app.use("/.well-known", (req, res, next) => {
  // CORS for discovery endpoints
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  next();
});
app.use("/.well-known", express.static("/source/.well-known"));

// ---------------------------------------------------------------------------
// Child process management (docdexd mcp)
// ---------------------------------------------------------------------------

let child = null;
let childConfig = null; // { repoPath, logLevel, maxResults }
let stdoutBuffer = "";
const pending = new Map(); // id(string) -> { resolve, reject }

function normalizeConfig(overrides = {}) {
  const repoPath =
    typeof overrides.repoPath === "string" && overrides.repoPath.trim()
      ? overrides.repoPath.trim()
      : DEFAULT_REPO;

  const logLevel =
    typeof overrides.logLevel === "string" && overrides.logLevel.trim()
      ? overrides.logLevel.trim()
      : DEFAULT_LOG;

  const maxRaw = overrides.maxResults ?? DEFAULT_MAX_RESULTS;
  const maxNum = Number(maxRaw);
  const maxResults =
    Number.isFinite(maxNum) && maxNum > 0 ? maxNum : DEFAULT_MAX_RESULTS;

  return { repoPath, logLevel, maxResults };
}

function startDocdex(config) {
  const { repoPath, logLevel, maxResults } = config;

  console.log(
    `[Adapter] Starting docdexd mcp --repo=${repoPath} --log=${logLevel} --max-results=${maxResults}`
  );

  const args = [
    "mcp",
    "--repo",
    repoPath,
    "--log",
    logLevel,
    "--max-results",
    String(maxResults),
  ];

  const proc = spawn("docdexd", args);

  proc.stderr.on("data", (data) => {
    console.error("[docdexd]", data.toString());
  });

  proc.stdout.on("data", (chunk) => {
    stdoutBuffer += chunk.toString();
    let idx;
    while ((idx = stdoutBuffer.indexOf("\n")) !== -1) {
      const line = stdoutBuffer.slice(0, idx).trim();
      stdoutBuffer = stdoutBuffer.slice(idx + 1);
      if (!line) continue;

      let msg;
      try {
        msg = JSON.parse(line);
      } catch (err) {
        console.error(
          "[Adapter] Failed to parse JSON from docdexd:",
          err,
          "line:",
          line
        );
        continue;
      }

      if (Object.prototype.hasOwnProperty.call(msg, "id")) {
        const key = String(msg.id);
        const entry = pending.get(key);
        if (entry) {
          pending.delete(key);
          entry.resolve(msg);
        } else {
          console.log("[Adapter] Unmatched response from docdexd:", msg);
        }
      } else {
        // Notifications from docdexd
        console.log("[Adapter] Notification from docdexd:", msg);
      }
    }
  });

  proc.on("exit", (code, signal) => {
    console.warn(`[Adapter] docdexd exited (code=${code}, signal=${signal})`);
    if (child === proc) {
      child = null;
      childConfig = null;
      stdoutBuffer = "";
    }
    for (const { reject } of pending.values()) {
      reject(new Error("docdexd process exited"));
    }
    pending.clear();
  });

  child = proc;
  childConfig = config;
  return proc;
}

function ensureDocdex(configOverrides = {}) {
  const desired = normalizeConfig(configOverrides);

  if (child && !child.killed && childConfig) {
    const same =
      childConfig.repoPath === desired.repoPath &&
      childConfig.logLevel === desired.logLevel &&
      childConfig.maxResults === desired.maxResults;

    if (same) return child;

    console.log("[Adapter] Restarting docdexd with new config");
    child.kill();
  }

  return startDocdex(desired);
}

function decodeConfig(req) {
  const raw = req.query?.config;
  if (!raw) return {};

  try {
    const json = Buffer.from(String(raw), "base64").toString("utf8");
    const parsed = JSON.parse(json);
    if (parsed && typeof parsed === "object") return parsed;
  } catch (err) {
    console.error("[Adapter] Failed to decode config query param:", err);
  }
  return {};
}

function sendRequestToDocdex(message, configOverrides = {}) {
  const proc = ensureDocdex(configOverrides);
  const id = message.id;
  const key = String(id);

  return new Promise((resolve, reject) => {
    pending.set(key, { resolve, reject });

    try {
      const payload = JSON.stringify(message) + "\n";
      proc.stdin.write(payload, (err) => {
        if (err) {
          console.error("[Adapter] Failed to write to docdexd stdin:", err);
          if (pending.has(key)) {
            pending.get(key).reject(err);
            pending.delete(key);
          }
        }
      });
    } catch (err) {
      if (pending.has(key)) {
        pending.get(key).reject(err);
        pending.delete(key);
      }
      return;
    }

    // Simple timeout so we don't hang forever
    const timeoutMs = 15000;
    setTimeout(() => {
      if (pending.has(key)) {
        pending.get(key).reject(
          new Error("Timeout waiting for response from docdexd")
        );
        pending.delete(key);
      }
    }, timeoutMs);
  });
}

function sendNotificationToDocdex(message, configOverrides = {}) {
  const proc = ensureDocdex(configOverrides);
  try {
    const payload = JSON.stringify(message) + "\n";
    proc.stdin.write(payload);
  } catch (err) {
    console.error("[Adapter] Failed to send notification to docdexd:", err);
  }
}

// ---------------------------------------------------------------------------
// MCP prompts (implemented in adapter)
// ---------------------------------------------------------------------------

const DOCDEX_PROMPTS_LIST = {
  prompts: [
    {
      name: "docdex_repo_search",
      description:
        "Plan how to use Docdex tools to answer a question about this repository.",
      arguments: [
        {
          name: "question",
          description: "Question about this repository or its documentation.",
          required: true,
        },
      ],
    },
  ],
};

function handlePromptsList(message) {
  return {
    jsonrpc: "2.0",
    id: message.id,
    result: DOCDEX_PROMPTS_LIST,
  };
}

function handlePromptsCall(message) {
  const params = message.params || {};
  const name = params.name;
  const args = params.arguments || {};

  if (name !== "docdex_repo_search") {
    return {
      jsonrpc: "2.0",
      id: message.id,
      error: {
        code: -32601,
        message: `Unknown prompt: ${name}`,
      },
    };
  }

  const question = String(args.question || "").trim();

  const messages = [
    {
      role: "system",
      content: [
        {
          type: "text",
          text:
            "You have access to Docdex MCP tools for this repository. " +
            "Use docdex_search to find relevant docs, then docdex_open or docdex_files " +
            "for detailed context. Cite file paths in your answer.",
        },
      ],
    },
    {
      role: "user",
      content: [
        {
          type: "text",
          text:
            `Question: ${question}\n\n` +
            "Plan:\n" +
            "1. Call docdex_search with a short query.\n" +
            "2. Skim summaries/snippets.\n" +
            "3. Use docdex_open/docdex_files for details.\n" +
            "4. Answer using only those docs.",
        },
      ],
    },
  ];

  return {
    jsonrpc: "2.0",
    id: message.id,
    result: { messages },
  };
}

// ---------------------------------------------------------------------------
// MCP resources (simple static help resource)
// ---------------------------------------------------------------------------

const DOCDEX_RESOURCES = [
  {
    uri: "docdex://help",
    name: "Docdex MCP usage guide",
    description:
      "How to use docdex_search, docdex_index, docdex_files, docdex_open and docdex_stats.",
    mimeType: "text/markdown",
  },
];

const DOCDEX_RESOURCE_CONTENT = {
  "docdex://help": {
    uri: "docdex://help",
    mimeType: "text/markdown",
    text: [
      "# Docdex MCP Usage",
      "",
      "- Use `docdex_search` first to find relevant docs.",
      "- If results look stale, call `docdex_index` to rebuild the index.",
      "- Use `docdex_files` to browse indexed files.",
      "- Use `docdex_open` to read a specific file or line range.",
      "- Use `docdex_stats` to inspect index statistics.",
      "",
      "Keep queries short and focused. Include file paths in your answer when possible.",
    ].join("\n"),
  },
};

function handleResourcesList(message) {
  return {
    jsonrpc: "2.0",
    id: message.id,
    result: { resources: DOCDEX_RESOURCES },
  };
}

function handleResourcesRead(message) {
  const params = message.params || {};
  const uris = params.uris || [];
  const contents = [];

  for (const uri of uris) {
    if (DOCDEX_RESOURCE_CONTENT[uri]) {
      contents.push(DOCDEX_RESOURCE_CONTENT[uri]);
    }
  }

  return {
    jsonrpc: "2.0",
    id: message.id,
    result: { contents },
  };
}

// ---------------------------------------------------------------------------
// Tool annotations (for Smithery Tool Quality score)
// ---------------------------------------------------------------------------

function annotateTool(tool) {
  const base = tool.annotations || {};

  switch (tool.name) {
    case "docdex_search":
      return {
        ...tool,
        annotations: {
          ...base,
          category: "search",
          preferred: true,
          purpose:
            "Search repository documentation with a natural-language query.",
        },
      };

    case "docdex_index":
      return {
        ...tool,
        annotations: {
          ...base,
          category: "maintenance",
          purpose: "Rebuild or refresh the Docdex index.",
        },
      };

    case "docdex_files":
      return {
        ...tool,
        annotations: {
          ...base,
          category: "navigation",
          purpose: "List indexed documentation files.",
        },
      };

    case "docdex_open":
      return {
        ...tool,
        annotations: {
          ...base,
          category: "navigation",
          purpose: "Open a specific file or line range from the index.",
        },
      };

    case "docdex_stats":
      return {
        ...tool,
        annotations: {
          ...base,
          category: "introspection",
          purpose: "Inspect index size and statistics.",
        },
      };

    default:
      return {
        ...tool,
        annotations: {
          ...base,
          category: "other",
        },
      };
  }
}

// ---------------------------------------------------------------------------
// Streamable HTTP MCP endpoint
// ---------------------------------------------------------------------------

app.post("/mcp", async (req, res) => {
  const message = req.body;

  if (!message || message.jsonrpc !== "2.0") {
    return res.status(400).json({
      jsonrpc: "2.0",
      id: null,
      error: {
        code: -32600,
        message: "Invalid JSON-RPC 2.0 message",
      },
    });
  }

  const hasId = Object.prototype.hasOwnProperty.call(message, "id");
  const method = message.method;
  const configOverrides = decodeConfig(req);

  // Notifications (no id) – fire-and-forget
  if (!hasId) {
    if (method) {
      sendNotificationToDocdex(message, configOverrides);
    }
    return res.status(204).end();
  }

  // Prompts implemented in adapter
  if (method === "prompts/list") {
    return res.json(handlePromptsList(message));
  }
  if (method === "prompts/call") {
    return res.json(handlePromptsCall(message));
  }

  // Resources implemented in adapter
  if (method === "resources/list") {
    return res.json(handleResourcesList(message));
  }
  if (method === "resources/read") {
    return res.json(handleResourcesRead(message));
  }

  // Wrap tools/list to inject annotations
  if (method === "tools/list") {
    try {
      const response = await sendRequestToDocdex(message, configOverrides);
      if (response?.result?.tools && Array.isArray(response.result.tools)) {
        response.result.tools = response.result.tools.map(annotateTool);
      }
      return res.json(response);
    } catch (err) {
      console.error("[Adapter] tools/list error:", err);
      return res.status(500).json({
        jsonrpc: "2.0",
        id: message.id,
        error: {
          code: -32000,
          message: err?.message || "Internal error in tools/list wrapper",
        },
      });
    }
  }

  // Everything else -> pure proxy to docdexd
  try {
    const response = await sendRequestToDocdex(message, configOverrides);
    return res.json(response);
  } catch (err) {
    console.error("[Adapter] /mcp error:", err);
    return res.status(500).json({
      jsonrpc: "2.0",
      id: message.id,
      error: {
        code: -32000,
        message: err?.message || "Internal MCP adapter error",
      },
    });
  }
});

// ---------------------------------------------------------------------------
// Optional SSE transport (for compatibility)
// ---------------------------------------------------------------------------

app.get("/sse", (req, res) => {
  const configOverrides = decodeConfig(req);
  const proc = ensureDocdex(configOverrides);

  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
  });

  console.log("[Adapter] New SSE connection");

  // Tell client where to POST messages
  res.write(`event: endpoint\ndata: /message\n\n`);

  const onStdout = (chunk) => {
    const lines = chunk.toString().split("\n");
    for (const line of lines) {
      if (line.trim()) {
        res.write(`event: message\ndata: ${line}\n\n`);
      }
    }
  };

  proc.stdout.on("data", onStdout);

  req.on("close", () => {
    console.log("[Adapter] SSE connection closed");
    proc.stdout.off("data", onStdout);
  });
});

app.post("/message", (req, res) => {
  const configOverrides = decodeConfig(req);
  sendNotificationToDocdex(req.body, configOverrides);
  res.status(202).send("Accepted");
});

// ---------------------------------------------------------------------------
// Start server
// ---------------------------------------------------------------------------

app.listen(PORT, () => {
  console.log(`Docdex MCP adapter listening on port ${PORT}`);
  console.log(`Default repo path: ${DEFAULT_REPO}`);
});
