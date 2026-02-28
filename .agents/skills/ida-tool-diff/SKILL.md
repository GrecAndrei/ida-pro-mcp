# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`diff`

## Use This Skill When
- You need to call the `diff` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Binary differential analysis. Actions: functions, bytes, signatures, summary, export_binexport.

## Actions
- `functions`
- `bytes`
- `signatures`
- `summary`
- `export_binexport`

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
