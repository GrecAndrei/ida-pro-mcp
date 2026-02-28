# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`xfer_analysis`

## Use This Skill When
- You need to call the `xfer_analysis` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Alias of xref_analysis (compatibility typo, not advertised in tools/list).

## Actions
- `call_chain`
- `common_callers`
- `common_callees`
- `hub_functions`
- `leaf_functions`
- `recursive`
- `dominator`
- `influence`
- `dependency_graph`
- `dead_functions`

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
