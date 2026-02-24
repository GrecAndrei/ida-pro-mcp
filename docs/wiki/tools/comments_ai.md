# COMMENTS_AI Tool Manual

## What It Does
AI-optimized comment management with structured formats and bulk operations.

## Actions
- `get_context`: Collect nearby code/comments context for an address.
- `set_structured`: Set a structured comment payload at an address.
- `bulk_set`: Apply structured comments in bulk.
- `export_md`: Export comments to markdown.
- `import_md`: Import comments from markdown.
- `summary`: Generate a compact comment summary view.

## Key Parameters
- `action` (required): Operation selector.
- `addr` (default `None`): Target address or function start (hex string).
- `text` (default `None`): Comment text payload for comment-writing actions.
- `items` (default `None`): Structured list payload for bulk operations.
- `path` (default `None`): Filesystem path for import/export input.
- `format` (default `'plain'`): Output/input format (`json`, `plain`, `md`, etc. as supported).

## Examples (JSON call snippets)
```json
{
  "tool": "comments_ai",
  "args": {
    "action": "get_context",
    "addr": "0x401000"
  }
}
```
```json
{
  "tool": "comments_ai",
  "args": {
    "action": "bulk_set",
    "items": [
      {
        "addr": "0x401000",
        "text": "Initializes session state"
      },
      {
        "addr": "0x401050",
        "text": "Validates token"
      }
    ]
  }
}
```

## Failure Modes
- `INVALID_ARGS`: `addr required`
- `INVALID_ARGS`: `addr and text required`
- `INVALID_ARGS`: `items required (JSON list)`
- `INVALID_ARGS`: `Invalid JSON: {e}`
- `INVALID_ARGS`: `items must be a JSON array`
- `INVALID_ARGS`: `path required`
- `INVALID_ARGS`: `Unknown action: {action}`
