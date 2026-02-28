# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`stack_analysis`

## Use This Skill When
- You need to call the `stack_analysis` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Stack frame analysis. Actions: frame, buffers, canary, alignment, spills, usage, variables, arrays, uninitialized, summary.

## Actions
- `frame`
- `buffers`
- `canary`
- `alignment`
- `spills`
- `usage`
- `variables`
- `arrays`
- `uninitialized`
- `summary`

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
