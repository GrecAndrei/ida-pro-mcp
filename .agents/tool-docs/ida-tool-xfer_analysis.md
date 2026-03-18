# IDA MCP Tool Doc: `xfer_analysis`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `xfer_analysis` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Alias of xref_analysis (compatibility typo, not advertised in tools/list).

## Actions
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
- `grep` (host wrapper): run another action, then grep its output lines.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/xfer_analysis')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "xfer_analysis",
  "arguments": {
    "action": "call_chain"
  }
}
```
```json
{
  "name": "xfer_analysis",
  "arguments": {
    "action": "grep",
    "source_action": "call_chain",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
