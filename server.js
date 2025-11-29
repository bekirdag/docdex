import express from 'express';
import bodyParser from 'body-parser';
import { spawn } from 'child_process';

const app = express();
const PORT = process.env.PORT || 8080;

// Defaults (can be overridden by Smithery config)
const FALLBACK_REPO = '/source';
const FALLBACK_LOG = 'warn';
const FALLBACK_MAX = 8;

let activeConfig = {
  repoPath: FALLBACK_REPO,
  logLevel: FALLBACK_LOG,
  maxResults: FALLBACK_MAX,
};

let child = null;
let stdoutBuffer = '';
const pending = new Map(); // id -> { resolve, reject }

// --- Helper: decode Smithery config from ?config=<base64> ---
function decodeConfig(req) {
  const raw = req.query?.config;
  if (!raw) return {};

  try {
    const json = Buffer.from(String(raw), 'base64').toString('utf8');
    const parsed = JSON.parse(json);
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch (err) {
    console.error('[Adapter] Failed to decode config param:', err);
    return {};
  }
}

// --- Start / manage docdexd mcp child process ---
function startDocdex(configOverrides = {}) {
  if (child && !child.killed) {
    return child;
  }

  activeConfig = {
    ...activeConfig,
    ...configOverrides,
  };

  const repoPath = activeConfig.repoPath || FALLBACK_REPO;
  const logLevel = activeConfig.logLevel || FALLBACK_LOG;
  const maxResults = String(
    activeConfig.maxResults || FALLBACK_MAX,
  );

  console.log(
    `[Adapter] Starting docdexd mcp --repo=${repoPath} --log=${logLevel} --max-results=${maxResults}`,
  );

  child = spawn('docdexd', [
    'mcp',
    '--repo',
    repoPath,
    '--log',
    logLevel,
    '--max-results',
    maxResults,
  ]);

  child.stdout.on('data', (chunk) => {
    stdoutBuffer += chunk.toString();
    let idx;
    while ((idx = stdoutBuffer.indexOf('\n')) !== -1) {
      const line = stdoutBuffer.slice(0, idx).trim();
      stdoutBuffer = stdoutBuffer.slice(idx + 1);
      if (!line) continue;

      let msg;
      try {
        msg = JSON.parse(line);
      } catch (err) {
        console.error('[Adapter] Invalid JSON from docdexd:', line);
        continue;
      }

      if (Object.prototype.hasOwnProperty.call(msg, 'id')) {
        const key = String(msg.id);
        const pendingEntry = pending.get(key);
        if (pendingEntry) {
          pending.delete(key);
          pendingEntry.resolve(msg);
        } else {
          console.log('[Adapter] Unmatched message from docdexd:', msg);
        }
      } else {
        // Notifications from docdexd – just log.
        console.log('[Adapter] Notification from docdexd:', msg);
      }
    }
  });

  child.stderr.on('data', (data) => {
    console.error('[docdexd]', data.toString());
  });

  child.on('exit', (code, signal) => {
    console.warn(`[Adapter] docdexd exited (code=${code}, signal=${signal})`);
    for (const entry of pending.values()) {
      entry.reject(new Error('docdexd exited'));
    }
    pending.clear();
    child = null;
  });

  return child;
}

function sendNotificationToDocdex(message, configOverrides = {}) {
  startDocdex(configOverrides);
  try {
    child.stdin.write(JSON.stringify(message) + '\n');
  } catch (err) {
    console.error('[Adapter] Failed to send notification to docdexd:', err);
  }
}

// JSON-RPC request (expects a response)
function sendRequestToDocdex(message, configOverrides = {}) {
  startDocdex(configOverrides);
  const id = message.id;
  const key = String(id);

  return new Promise((resolve, reject) => {
    pending.set(key, { resolve, reject });

    child.stdin.write(JSON.stringify(message) + '\n', (err) => {
      if (err) {
        console.error('[Adapter] Failed to write to docdexd:', err);
        if (pending.has(key)) {
          pending.get(key).reject(err);
          pending.delete(key);
        }
      }
    });

    // Optional: timeout
    setTimeout(() => {
      if (pending.has(key)) {
        pending.delete(key);
        reject(new Error('Timeout waiting for response from docdexd'));
      }
    }, 15000);
  });
}

// --- MCP Prompts (in adapter) ---

const PROMPTS_LIST_RESULT = {
  prompts: [
    {
      name: 'docdex_repo_search',
      description:
        'Use Docdex tools to search this repository documentation and answer questions.',
      arguments: [
        {
          name: 'question',
          description: 'Question about this repository or its documentation.',
          required: true,
        },
      ],
    },
  ],
};

function handlePromptsList(message) {
  return {
    jsonrpc: '2.0',
    id: message.id,
    result: PROMPTS_LIST_RESULT,
  };
}

function handlePromptsCall(message) {
  const params = message.params || {};
  const name = params.name;
  const args = params.arguments || {};

  if (name !== 'docdex_repo_search') {
    return {
      jsonrpc: '2.0',
      id: message.id,
      error: {
        code: -32601,
        message: `Unknown prompt: ${name}`,
      },
    };
  }

  const question = String(args.question || '').trim();

  const messages = [
    {
      role: 'system',
      content: [
        {
          type: 'text',
          text:
            'You have access to Docdex MCP tools for this repository. ' +
            'Use docdex_search first to find relevant docs, then docdex_open or docdex_files for details. ' +
            'Cite file paths in your answer.',
        },
      ],
    },
    {
      role: 'user',
      content: [
        {
          type: 'text',
          text:
            `Question: ${question}\n\n` +
            'Plan:\n' +
            '1. Call the docdex_search tool with a short query.\n' +
            '2. Skim summaries/snippets.\n' +
            '3. Use docdex_open / docdex_files if you need full context.\n' +
            '4. Answer using only those docs.',
        },
      ],
    },
  ];

  return {
    jsonrpc: '2.0',
    id: message.id,
    result: { messages },
  };
}

// --- MCP Resources (in adapter) ---

const STATIC_RESOURCES = [
  {
    uri: 'docdex://help',
    name: 'Docdex MCP usage guide',
    description:
      'Short guide on how to use Docdex tools (search, index, files, open, stats) inside an AI agent.',
    mimeType: 'text/markdown',
  },
];

const RESOURCE_CONTENT = {
  'docdex://help': {
    uri: 'docdex://help',
    mimeType: 'text/markdown',
    text: [
      '# Docdex MCP usage',
      '',
      '- Use `docdex_search` first to find relevant docs.',
      '- If results look stale, call `docdex_index` to rebuild the index.',
      '- Browse indexed docs with `docdex_files`.',
      '- Open a specific file or span with `docdex_open`.',
      '- Inspect index stats with `docdex_stats`.',
      '',
      'Keep queries short and focused. Use file paths in your answers.',
    ].join('\n'),
  },
};

function handleResourcesList(message) {
  return {
    jsonrpc: '2.0',
    id: message.id,
    result: { resources: STATIC_RESOURCES },
  };
}

function handleResourcesRead(message) {
  const params = message.params || {};
  const uris = params.uris || [];
  const contents = [];

  for (const uri of uris) {
    const entry = RESOURCE_CONTENT[uri];
    if (entry) contents.push(entry);
  }

  return {
    jsonrpc: '2.0',
    id: message.id,
    result: { contents },
  };
}

// --- Tool annotations wrapper ---

function annotateTool(tool) {
  const baseAnnotations = tool.annotations || {};

  switch (tool.name) {
    case 'docdex_search':
      return {
        ...tool,
        annotations: {
          ...baseAnnotations,
          category: 'search',
          preferred: true,
          purpose: 'Search repository docs by natural language query.',
        },
      };
    case 'docdex_index':
      return {
        ...tool,
        annotations: {
          ...baseAnnotations,
          category: 'maintenance',
          purpose: 'Rebuild the Docdex index when results look stale.',
        },
      };
    case 'docdex_files':
      return {
        ...tool,
        annotations: {
          ...baseAnnotations,
          category: 'navigation',
          purpose: 'List indexed documentation files.',
        },
      };
    case 'docdex_open':
      return {
        ...tool,
        annotations: {
          ...baseAnnotations,
          category: 'navigation',
          purpose: 'Open a specific file or line range from the index.',
        },
      };
    case 'docdex_stats':
      return {
        ...tool,
        annotations: {
          ...baseAnnotations,
          category: 'introspection',
          purpose: 'Inspect index size and basic statistics.',
        },
      };
    default:
      return {
        ...tool,
        annotations: {
          ...baseAnnotations,
          category: 'other',
        },
      };
  }
}

// --- MCP Server Card (for icon + metadata) ---

const SERVER_CARD = {
  version: '1.0',
  protocolVersion: '2025-06-18',
  serverInfo: {
    name: 'docdex',
    title: 'Docdex – Repo Docs Index & Search',
    version: process.env.DOCDEX_VERSION || '0.1.6',
  },
  description:
    'Per-repo documentation indexer and search daemon exposing docdex tools over MCP.',
  iconUrl: 'https://docdex.org/assets/docdex.png', // change this to your actual icon
  documentationUrl: 'https://docdex.org/',
  transport: {
    type: 'streamable-http',
    endpoint: '/mcp',
    sseEndpoint: '/mcp',
  },
  capabilities: {
    tools: { listChanged: true },
    prompts: { listChanged: true },
    resources: { listChanged: true },
  },
  instructions:
    'Use docdex_search to find relevant docs before coding. ' +
    'Call docdex_index when results look stale, docdex_files to browse, ' +
    'docdex_open for detailed spans, and docdex_stats to inspect the index.',
  resources: ['dynamic'],
  tools: ['dynamic'],
  prompts: ['dynamic'],
};

// --- Express wiring ---

app.use(bodyParser.json());

// Server card (metadata + icon)
app.get('/.well-known/mcp.json', (req, res) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.json(SERVER_CARD);
});

// Streamable HTTP MCP endpoint
app.post('/mcp', async (req, res) => {
  const message = req.body;

  if (!message || message.jsonrpc !== '2.0') {
    return res.status(400).json({
      jsonrpc: '2.0',
      id: null,
      error: {
        code: -32600,
        message: 'Invalid JSON-RPC 2.0 message',
      },
    });
  }

  const hasId = Object.prototype.hasOwnProperty.call(message, 'id');
  const id = hasId ? message.id : null;
  const method = message.method;
  const configOverrides = decodeConfig(req);

  try {
    // Notifications (no id) – forward to docdexd, return 204
    if (!hasId) {
      if (method) {
        sendNotificationToDocdex(message, configOverrides);
      }
      return res.status(204).send();
    }

    // Prompts implemented in adapter
    if (method === 'prompts/list') {
      return res.json(handlePromptsList(message));
    }
    if (method === 'prompts/call') {
      return res.json(handlePromptsCall(message));
    }

    // Resources implemented in adapter
    if (method === 'resources/list') {
      return res.json(handleResourcesList(message));
    }
    if (method === 'resources/read') {
      return res.json(handleResourcesRead(message));
    }

    // Wrap tools/list to inject annotations
    if (method === 'tools/list') {
      const response = await sendRequestToDocdex(message, configOverrides);
      if (response && response.result && Array.isArray(response.result.tools)) {
        response.result.tools = response.result.tools.map(annotateTool);
      }
      return res.json(response);
    }

    // Everything else -> proxy to docdexd
    const response = await sendRequestToDocdex(message, configOverrides);
    return res.json(response);
  } catch (err) {
    console.error('[Adapter] Error handling /mcp request:', err);
    return res.status(500).json({
      jsonrpc: '2.0',
      id,
      error: {
        code: -32000,
        message: err.message || 'Internal error in adapter',
      },
    });
  }
});

app.listen(PORT, () => {
  console.log(`Docdex MCP adapter listening on port ${PORT}`);
  console.log(`Default repo path: ${activeConfig.repoPath}`);
});
