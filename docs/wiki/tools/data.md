# DATA Tool Manual

## What It Does
Query, filter, and list data items: functions, globals, strings, imports.

## Actions
- `functions`: List/query functions with filters.
- `globals`: List/query global data symbols.
- `strings`: List/query discovered strings.
- `imports`: List imports and related metadata.
- `exports`: List exports and related metadata.
- `lookup`: Resolve a symbol/name/address query.
- `bulk_query`: Run mixed data queries in one request.

## Key Parameters
- `action` (required): Operation selector.
- `query` (default `None`): Search query string or query payload.
- `offset` (default `0`): Pagination offset or base offset.
- `count` (default `100`): Item count or array length.
- `include_prototype` (default `False`): Include function prototypes in data listings.
- `include_xrefs` (default `False`): Include xref details in listing output.
- `min_size` (default `None`): Minimum size filter for data results.
- `named_only` (default `False`): Restrict to named symbols/items.

## Examples (JSON call snippets)
```json
{
  "tool": "data",
  "args": {
    "action": "functions",
    "count": 50,
    "include_prototype": true
  }
}
```
```json
{
  "tool": "data",
  "args": {
    "action": "lookup",
    "query": "sub_401000",
    "include_xrefs": true
  }
}
```

## Failure Modes
- `IDA_ERROR`: `Entry API not available in this IDA version`
- `INVALID_ARGS`: `query required for lookup`
- `INVALID_ARGS`: `items must be a list`
- `INVALID_ARGS`: `Unknown action: {action}`
