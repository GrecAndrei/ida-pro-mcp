# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`nav`

## Use This Skill When
- You need to call the `nav` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Navigation and triage. Actions: goto, cursor, interesting.

## Actions
- `goto`
- `cursor`
- `interesting`

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
