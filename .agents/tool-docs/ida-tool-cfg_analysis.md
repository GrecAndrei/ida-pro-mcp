# IDA MCP Tool Doc: `cfg_analysis`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `cfg_analysis` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

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
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
