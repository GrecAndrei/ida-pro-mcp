# IDA MCP Tool Doc: `annotation`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `annotation` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Intelligent bulk annotation (writes to DB, supports dry_run). Actions: auto_comment, label_loops, label_branches, mark_dangerous, annotate_constants, tag_functions, document_args, mark_error_paths, propagate_names, cleanup.

## Actions
- `auto_comment`
- `label_loops`
- `label_branches`
- `mark_dangerous`
- `annotate_constants`
- `tag_functions`
- `document_args`
- `mark_error_paths`
- `propagate_names`
- `cleanup`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
