# IDA MCP Tool Doc: `annotation`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `annotation` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Automatically generates and manages comments, labels, and documentation across functions. Actions: auto_comment, auto_comment_function, label_loops, label_branches, mark_dangerous, annotate_constants, tag_functions, document_args, mark_error_paths, propagate_names, cleanup, validate, get_context, set_structured, bulk_set, export_md, import_md, summary.

## Actions
- `auto_comment` (tool-specific)
- `auto_comment_function` (tool-specific)
- `label_loops` (tool-specific)
- `label_branches` (tool-specific)
- `mark_dangerous` (tool-specific)
- `annotate_constants` (tool-specific)
- `tag_functions` (tool-specific)
- `document_args` (tool-specific)
- `mark_error_paths` (tool-specific)
- `propagate_names` (tool-specific)
- `cleanup` (tool-specific)
- `validate` (tool-specific)
- `get_context` (tool-specific)
- `set_structured` (tool-specific)
- `bulk_set` (tool-specific)
- `export_md` (tool-specific)
- `import_md` (tool-specific)
- `summary` (read/discovery)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/annotation')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "annotation",
  "arguments": {
    "action": "auto_comment"
  }
}
```
```json
{
  "name": "annotation",
  "arguments": {
    "action": "grep",
    "source_action": "auto_comment",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
