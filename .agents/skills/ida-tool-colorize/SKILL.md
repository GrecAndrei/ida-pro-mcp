# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`colorize`

## Use This Skill When
- You need to call the `colorize` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Visual highlighting. Actions: set_func, set_range, set_insn, get, clear, palette, highlight_pattern.

## Actions
- `set_func`
- `set_range`
- `set_insn`
- `get`
- `clear`
- `palette`
- `highlight_pattern`

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
