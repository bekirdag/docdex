import express from 'express';
import { spawn } from 'child_process';
import bodyParser from 'body-parser';

const app = express();
const port = process.env.PORT || 8080;

// Default config
const DEFAULT_REPO = "/source";
const DEFAULT_LOG = "warn";
const DEFAULT_MAX = "8";

app.use(bodyParser.json());

// 1. SSE Endpoint: Smithery connects here to start the session
app.get('/sse', (req, res) => {
  // Set headers for Server-Sent Events
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
  });

  console.log(`[Adapter] New SSE connection. Spawning docdexd...`);

  // Start the Rust binary in MCP mode
  const child = spawn('docdexd', [
    'mcp',
    '--repo', DEFAULT_REPO,
    '--log', DEFAULT_LOG,
    '--max-results', DEFAULT_MAX
  ]);

  // Tell Smithery where to send POST messages
  res.write(`event: endpoint\ndata: /message\n\n`);

  // Pipe Rust STDOUT (JSON-RPC) --> HTTP Response (SSE)
  child.stdout.on('data', (chunk) => {
    const lines = chunk.toString().split('\n');
    for (const line of lines) {
      if (line.trim()) {
        res.write(`event: message\ndata: ${line}\n\n`);
      }
    }
  });

  // Log Errors
  child.stderr.on('data', (data) => console.error(`[Docdex Stderr] ${data}`));

  // Cleanup: Kill the binary when the HTTP connection closes
  req.on('close', () => {
    console.log('[Adapter] Connection closed, killing process.');
    child.kill();
  });

  // Save the process reference for the POST handler (Simple single-session approach)
  // In a production multi-user env, you would map session IDs. 
  // For Smithery single-deployment, this simple closure global works.
  app.locals.childProcess = child;
});

// 2. Message Endpoint: Smithery sends JSON-RPC commands here
app.post('/message', (req, res) => {
  const child = app.locals.childProcess;
  
  if (!child) {
    return res.status(500).send("No active MCP session found. Connect to /sse first.");
  }

  // Pipe HTTP Body (JSON-RPC) --> Rust STDIN
  const message = JSON.stringify(req.body) + "\n";
  child.stdin.write(message);
  
  res.status(202).send("Accepted");
});

app.listen(port, () => {
  console.log(`Docdex Adapter listening on port ${port}`);
  console.log(`Indexing path: ${DEFAULT_REPO}`);
});