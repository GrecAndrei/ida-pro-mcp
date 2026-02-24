# AGENT Tool Manual

## What It Does
High-level agent helpers for efficient binary analysis.

## Actions
- `analyze_function`: Build a compact function summary with related context.
- `explore_address`: Expand context around an address (calls, xrefs, nearby symbols).
- `find_references`: Collect references to a target address or symbol.
- `search_all`: Search names, strings, imports, and symbols with one query.
- `search_structs`: Search structures and fields by query.
- `context_pack`: Return a bundled context payload for an address/function.
- `quick`: Fast lightweight overview for a location.
- `rename_suggestions`: Generate candidate symbol names from behavior/context.
- `batch_context`: Build context for multiple addresses in one request.
- `similar`: Find similar functions around the target.

## Key Parameters
- `action` (required): Operation selector.
- `addr` (default `None`): Target address or function start (hex string).
- `query` (default `None`): Search query string or query payload.
- `depth` (default `1`): Traversal/path depth bound.
- `include_pseudocode` (default `False`): Include decompiled pseudocode in agent output.
- `max_items` (default `25`): Maximum returned items.
- `use_cache` (default `True`): Use cached intermediate context when available.

## Examples (JSON call snippets)
```json
{
  "tool": "agent",
  "args": {
    "action": "analyze_function",
    "addr": "0x401000",
    "include_pseudocode": true
  }
}
```
```json
{
  "tool": "agent",
  "args": {
    "action": "search_all",
    "query": "credential",
    "max_items": 20
  }
}
```

## Failure Modes
- `INVALID_ARGS`: `addr required`
- `INVALID_ARGS`: `query required`
- `FUNCTION_NOT_FOUND`: `No function at {hex(ea)}`
- `INVALID_ARGS`: `query required (comma-separated addresses)`
- `INVALID_ARGS`: `Unknown action: {action}`
