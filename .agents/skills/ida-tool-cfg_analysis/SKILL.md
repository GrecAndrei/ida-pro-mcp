# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`cfg_analysis`

## Use This Skill When
- You need to call the `cfg_analysis` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Control flow graph metrics. Actions: complexity, loops, branches, paths, dominators, post_dominators, back_edges, natural_loops, irreducible, flatten_detect.

## Actions
- `complexity`
- `loops`
- `branches`
- `paths`
- `dominators`
- `post_dominators`
- `back_edges`
- `natural_loops`
- `irreducible`
- `flatten_detect`

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
