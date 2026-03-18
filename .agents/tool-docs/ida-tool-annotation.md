# IDA MCP Tool Doc: `annotation`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `annotation` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Intelligent bulk annotation (writes to DB, supports dry_run). Actions: auto_comment, label_loops, label_branches, mark_dangerous, annotate_constants, tag_functions, document_args, mark_error_paths, propagate_names, cleanup.

## Actions
- `auto_comment` (tool-specific)
- `label_loops` (tool-specific)
- `label_branches` (tool-specific)
- `mark_dangerous` (tool-specific)
- `annotate_constants` (tool-specific)
- `tag_functions` (tool-specific)
- `document_args` (tool-specific)
- `mark_error_paths` (tool-specific)
- `propagate_names` (tool-specific)
- `cleanup` (tool-specific)
- `grep` (host wrapper): run another action, then grep its output lines.

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
