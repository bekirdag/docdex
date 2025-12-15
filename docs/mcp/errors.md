# MCP Error Envelope (Docdex)

Docdex’s MCP server (`docdexd mcp`) reports tool failures as JSON-RPC errors. The machine-readable error code is carried in `error.data.code` (and duplicated under `error.data.error.code`).

## JSON-RPC shape

On failure, the MCP server returns a JSON-RPC error response:

- `error.code`: JSON-RPC error code (currently `-32602` for tool call failures and parameter validation failures).
- `error.message`: stable, human-readable summary for the category (e.g. `"invalid parameters"`, `"unknown repo"`).
- `error.data`: Docdex error data (see below).

## Docdex error data shape

`error.data` is an object with:

- `code` (string): machine-readable Docdex error code.
- `message` (string): short summary message (mirrors `error.message`).
- `reason` (string, optional): a more detailed reason, typically from the underlying error.
- `tool` (string, optional): tool name (e.g. `docdex_search`) when applicable.
- `details` (object, optional): structured context (field names, limits, etc) when available.
- `error` (object): the canonical envelope, containing the same fields as above (`code/message/reason/tool/details`).

## Standard machine-readable codes

These codes are used consistently across MCP tools, and are intended to match the daemon’s HTTP/CLI error codes for the same underlying failure:

- `missing_repo`
- `unknown_repo`
- `missing_index` (or `stale_index`)
- `missing_dependency`
- `rate_limited` (or `backoff_required`)
- `internal_error`

Parameter/argument validation failures use:

- `invalid_params` (schema/JSON type issues)
- `invalid_argument` (runtime validation failures like empty strings)
- Tool-specific validation codes where applicable (e.g. `invalid_query`, `invalid_path`, `invalid_range`)

