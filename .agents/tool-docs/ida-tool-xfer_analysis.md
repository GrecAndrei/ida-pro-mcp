# IDA MCP Tool Doc: `xfer_analysis`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `xfer_analysis` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

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
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
