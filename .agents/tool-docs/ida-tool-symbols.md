# IDA MCP Tool Doc: `symbols`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `symbols` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Loads and manages debug symbols (PDB/DWARF) for the current binary. Actions: load_pdb, load_dwarf, status, apply, export.

## Actions
- `load_pdb` (tool-specific)
- `load_dwarf` (tool-specific)
- `status` (read/discovery)
- `apply` (write/mutate)
- `export` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/symbols')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "symbols",
  "arguments": {
    "action": "load_pdb"
  }
}
```
```json
{
  "name": "symbols",
  "arguments": {
    "action": "grep",
    "source_action": "load_pdb",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
