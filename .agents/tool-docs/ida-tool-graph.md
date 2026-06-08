# IDA MCP Tool Doc: `graph`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `graph` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Generate call graphs, CFGs, xref graphs, and cross-reference graph analysis. Actions: callgraph, cfg, dominators, xref_graph, call_chain, common_callers, common_callees, hub_functions, leaf_functions, recursive, dominator, influence, dependency_graph, dead_functions.

## Actions
- `callgraph` (tool-specific)
- `cfg` (tool-specific)
- `dominators` (tool-specific)
- `xref_graph` (tool-specific)
- `call_chain` (tool-specific)
- `common_callers` (tool-specific)
- `common_callees` (tool-specific)
- `hub_functions` (tool-specific)
- `leaf_functions` (tool-specific)
- `recursive` (tool-specific)
- `dominator` (tool-specific)
- `influence` (tool-specific)
- `dependency_graph` (tool-specific)
- `dead_functions` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/graph')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "graph",
  "arguments": {
    "action": "callgraph"
  }
}
```
```json
{
  "name": "graph",
  "arguments": {
    "action": "grep",
    "source_action": "callgraph",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
