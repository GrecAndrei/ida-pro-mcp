# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`annotation`

## Use This Skill When
- You need to call the `annotation` tool.
- You want exact action/parameter contract without scanning global tool metadata.

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

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
