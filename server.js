import express from "express";
import { spawn } from "child_process";
import bodyParser from "body-parser";

const app = express();
const port = process.env.PORT || 8080;

// Defaults for docdex
const DEFAULT_REPO = process.env.DOCDEX_REPO || "/source";
const DEFAULT_LOG = process.env.DOCDEX_LOG || "warn";
const DEFAULT_MAX = process.env.DOCDEX_MAX_RESULTS || "8";

app.use(bodyParser.json());

// ---- Shared MCP child + routing for HTTP ----

let mcpChild = null;
let stdoutBuffer = "";
const pending = new Map(); // id -> { resolve, reject }

function ensureMcpChild() {
  if (mcpChild && !mcpChild.killed) {
    return mcpChild;
  }

  console.log("[Adapter] Spawning docdexd mcp process...");
  mcpChild = spawn("docdexd", [
    "mcp",
    "--repo",
    DEFAULT_REPO,
    "--log",
    DEFAULT_LOG,
    "--max-results",
    DEFAULT_MAX,
  ]);

  mcpChild.stderr.on("data", (data) => {
    console.error("[Docdex stderr]", data.toString());
  });

  mcpChild.on("exit", (code, signal) => {
    console.log(`[Adapter] docdexd exited code=${code} signal=${signal}`);
    for (const { reject } of pending.values()) {
      reject(new Error("docdexd process exited"));
    }
    pending.clear();
    stdoutBuffer = "";
    mcpChild = null;
  });

  // Parse JSON‑RPC lines from docdexd stdout
  mcpChild.stdout.on("data", (chunk) => {
    stdoutBuffer += chunk.toString();
    let idx;
    while ((idx = stdoutBuffer.indexOf("\n")) >= 0) {
      const line = stdoutBuffer.slice(0, idx).trim();
      stdoutBuffer = stdoutBuffer.slice(idx + 1);
      if (!line) continue;

      try {
        const msg = JSON.parse(line);
        const id = msg.id;
        if (id != null && pending.has(id)) {
          const { resolve } = pending.get(id);
          pending.delete(id);
          resolve(msg);
        } else {
          // Notifications / logs without an id
          console.log("[Adapter] Unmatched MCP message:", msg);
        }
      } catch (err) {
        console.error("[Adapter] Failed to parse MCP JSON:", err, "line:", line);
      }
    }
  });

  return mcpChild;
}

function sendJsonRpc(message) {
  return new Promise((resolve, reject) => {
    const child = ensureMcpChild();

    if (!message || typeof message !== "object") {
      return reject(new Error("Invalid JSON-RPC payload"));
    }

    const id = message.id;
    if (id === undefined || id === null) {
      return reject(new Error("JSON-RPC request must have an 'id'"));
    }

    if (pending.has(id)) {
      return reject(new Error(`Duplicate JSON-RPC id: ${id}`));
    }

    pending.set(id, { resolve, reject });

    try {
      const payload = JSON.stringify(message) + "\n";
      child.stdin.write(payload, (err) => {
        if (err) {
          pending.delete(id);
          reject(err);
        }
      });
    } catch (err) {
      pending.delete(id);
      reject(err);
    }

    // Simple timeout
    setTimeout(() => {
      if (pending.has(id)) {
        pending.delete(id);
        reject(new Error("JSON-RPC request timed out"));
      }
    }, 30_000);
  });
}

// ---- Streamable HTTP entrypoint (what Smithery hits) ----

app.post("/mcp", async (req, res) => {
  const msg = req.body;
  const child = ensureMcpChild();

  // 1) Notification (no id): fire-and-forget
  if (msg.id === undefined || msg.id === null) {
    try {
      const payload = JSON.stringify(msg) + "\n";
      child.stdin.write(payload);
      // JSON-RPC notifications don't have responses; HTTP can be 204 or 200 with empty body
      return res.status(204).end();
    } catch (err) {
      console.error("[Adapter] /mcp notification error:", err);
      return res.status(500).json({
        jsonrpc: "2.0",
        error: {
          code: -32000,
          message: err?.message || "Failed to send notification to MCP server",
        },
        id: null,
      });
    }
  }

  // 2) Normal request with id: go through sendJsonRpc and return its response
  try {
    const response = await sendJsonRpc(msg);
    res.json(response);
  } catch (err) {
    console.error("[Adapter] /mcp request error:", err);
    res.status(500).json({
      jsonrpc: "2.0",
      error: {
        code: -32000,
        message: err?.message || "Internal MCP adapter error",
      },
      id: msg.id,
    });
  }
});


// ---- SSE transport (kept, but now reuses the same child) ----

// 1. SSE: server → client
app.get("/sse", (req, res) => {
  const child = ensureMcpChild();

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

  child.stdout.on("data", onStdout);

  req.on("close", () => {
    console.log("[Adapter] SSE connection closed");
    child.stdout.off("data", onStdout);
    // We *don't* kill the child here so /mcp keeps working
  });
});

// 2. Message endpoint: client → server (used only with /sse)
app.post("/message", (req, res) => {
  const child = ensureMcpChild();

  const message = JSON.stringify(req.body) + "\n";
  child.stdin.write(message);

  res.status(202).send("Accepted");
});

app.listen(port, () => {
  console.log(`Docdex Adapter listening on port ${port}`);
  console.log(`Indexing path: ${DEFAULT_REPO}`);
});
