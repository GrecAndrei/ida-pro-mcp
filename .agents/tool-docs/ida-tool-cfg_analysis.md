# IDA MCP Tool Doc: `cfg_analysis`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `cfg_analysis` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Analyzes control flow graph structure including loops, dominators, and complexity. Actions: complexity, loops, branches, paths, dominators, post_dominators, back_edges, natural_loops, irreducible, flatten_detect.

## Actions
- `complexity` (tool-specific)
- `loops` (tool-specific)
- `branches` (tool-specific)
- `paths` (tool-specific)
- `dominators` (tool-specific)
- `post_dominators` (tool-specific)
- `back_edges` (tool-specific)
- `natural_loops` (tool-specific)
- `irreducible` (tool-specific)
- `flatten_detect` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/cfg_analysis')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "cfg_analysis",
  "arguments": {
    "action": "complexity"
  }
}
```
```json
{
  "name": "cfg_analysis",
  "arguments": {
    "action": "grep",
    "source_action": "complexity",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
