# BULK Tool Manual

## What It Does
Bulk operations for efficient multi-target modifications.

## Actions
- `rename`: Apply many renames in one operation.
- `comment`: Apply many comments in one operation.
- `apply_type`: Apply type information across multiple targets.
- `rename_stack`: Rename stack variables in bulk.
- `import_annotations`: Import saved annotations from a file.
- `export_annotations`: Export annotations to a file.

## Key Parameters
- `action` (required): Operation selector.
- `items` (default `None`): Structured list payload for bulk operations.
- `path` (default `None`): Filesystem path for import/export input.
- `continue_on_error` (default `True`): Continue processing remaining bulk items after failures.

## Examples (JSON call snippets)
```json
{
  "tool": "bulk",
  "args": {
    "action": "rename",
    "items": [
      {
        "addr": "0x401000",
        "name": "init_ctx"
      },
      {
        "addr": "0x401040",
        "name": "parse_cfg"
      }
    ]
  }
}
```
```json
{
  "tool": "bulk",
  "args": {
    "action": "import_annotations",
    "path": "./annotations.json",
    "continue_on_error": true
  }
}
```

## Failure Modes
- `INVALID_ARGS`: `items required`
- `INVALID_ARGS`: `path required`
- `INVALID_ARGS`: `Unknown action: {action}`
