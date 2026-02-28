# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`comments_ai`

## Use This Skill When
- You need to call the `comments_ai` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
AI-optimized comment management. Actions: get_context, set_structured, bulk_set, export_md, import_md, summary.

## Actions
- `get_context`
- `set_structured`
- `bulk_set`
- `export_md`
- `import_md`
- `summary`

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
