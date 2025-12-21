# DAG Export Schema v1 (`docdex.dag_export`)

Scope: per-session reasoning DAG export from the local state store. Applies to CLI `docdexd dag view` and HTTP `GET /v1/dag/export`.

## Storage source

- State file: `<state_dir>/dag.jsonl` (default `<repo>/.docdex/index/dag.jsonl`).
- Each line is a JSON object with:
  - `id` (string)
  - `session_id` (string)
  - `type` (string; e.g., `UserRequest`, `Thought`, `ToolCall`, `Observation`, `Decision`)
  - `payload` (object; optional, defaults to `{}`)
  - `created_at` (int; epoch ms)

## CLI usage

```
docdexd dag view --repo <path> <session_id> [--format json|text|dot] [--max-nodes <n>]
```

## HTTP usage

```
GET /v1/dag/export?session_id=<id>&format=json|text|dot&max_nodes=<n>
```

## JSON response (default)

```json
{
  "schema": { "name": "docdex.dag_export", "version": 1, "compatible": { "min": 1, "max": 1 } },
  "repoId": "<sha256 fingerprint>",
  "sessionId": "sess-123",
  "nodes": [
    { "id": "n1", "type": "UserRequest", "createdAt": 1700000000000, "payload": { "text": "hi" } },
    { "id": "n2", "type": "Observation", "createdAt": 1700000001000, "payload": {} }
  ],
  "edges": [
    { "source": "n1", "target": "n2" }
  ],
  "truncated": false,
  "appliedLimits": { "maxNodes": 200 }
}
```

### Ordering

- Nodes are sorted by `createdAt` ascending, then `id` ascending for deterministic output.
- Edges are derived by insertion order after sorting (`nodes[i] -> nodes[i+1]`).

## Text format

Text output is deterministic and omits payloads for stability:

```
session_id: sess-123
nodes: 2
n1	UserRequest	1700000000000
n2	Observation	1700000001000
edges:
n1 -> n2
truncated: false
```

## DOT format

Graphviz `digraph` with stable node/edge ordering. Node labels use the node `type` only.

```
digraph dag {
  "n1" [label="UserRequest"];
  "n2" [label="Observation"];
  "n1" -> "n2";
}
```

## Limits

- `max_nodes` defaults to `200`.
- `max_nodes` is clamped to a hard maximum of `5000`.
- When truncated, `truncated=true` and only the first `max_nodes` nodes (and their derived edges) are returned.

## Parity expectations

- CLI `docdexd dag view --format json` and HTTP `GET /v1/dag/export?format=json` return identical JSON for the same repo + session (aside from transport envelopes).
- Text/DOT formats are also deterministic and shared across surfaces.
