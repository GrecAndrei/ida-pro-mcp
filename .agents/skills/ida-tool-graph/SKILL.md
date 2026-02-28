# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`graph`

## Use This Skill When
- You need to call the `graph` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Topological visualization (CFG, callgraph). Actions: callgraph, cfg, xref_graph.

## Actions
- `callgraph`
- `cfg`
- `xref_graph`

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
