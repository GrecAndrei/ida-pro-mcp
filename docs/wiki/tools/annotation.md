# ANNOTATION Tool Manual

## What It Does
Intelligent bulk annotation tool optimized for LLMs.

## Actions
- `auto_comment`: Execute `auto_comment` workflow.
- `label_loops`: Execute `label_loops` workflow.
- `label_branches`: Execute `label_branches` workflow.
- `mark_dangerous`: Execute `mark_dangerous` workflow.
- `annotate_constants`: Execute `annotate_constants` workflow.
- `tag_functions`: Execute `tag_functions` workflow.
- `document_args`: Execute `document_args` workflow.
- `mark_error_paths`: Execute `mark_error_paths` workflow.
- `propagate_names`: Execute `propagate_names` workflow.
- `cleanup`: Execute `cleanup` workflow.

## Key Parameters
- `action` (required): Operation selector.
- `addr` (default `None`): Target address or function start (hex string).
- `limit` (default `100`): Maximum result count.
- `prefix` (default `'[MCP] '`): Prefix used when writing generated comments/tags.
- `dry_run` (default `False`): Preview actions without committing changes.

## Examples (JSON call snippets)
```json
{
  "tool": "annotation",
  "args": {
    "action": "auto_comment",
    "addr": "0x401000",
    "prefix": "[MCP] "
  }
}
```
```json
{
  "tool": "annotation",
  "args": {
    "action": "cleanup",
    "prefix": "[MCP] "
  }
}
```

## Failure Modes
- `INVALID_ARGS`: `addr required`
- `INVALID_ARGS`: `source function has default name (sub_) -`
- `INVALID_ARGS`: `Unknown action: {action}`
