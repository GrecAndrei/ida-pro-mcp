# BATCH Tool Manual

Run multiple tool calls in one request from the stdio MCP server. This tool is host-side and does not require an `idb` argument.

## Arguments
- `calls`: Array of tool call objects: `{ "name": "tool_name", "arguments": { ... } }`
- `continue_on_error`: Continue executing remaining calls after an error (default: false).

## Example
```json
{
  "calls": [
    { "name": "session", "arguments": { "action": "status" } },
    { "name": "calc", "arguments": { "action": "eval", "expr": "0x1000 + 0x20" } }
  ],
  "continue_on_error": true
}
```
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
