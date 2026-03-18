# IDA MCP Tool Doc: `coverage`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `coverage` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Code coverage import and analysis. Actions: import_drcov, import_lighthouse, highlight, report, uncovered, filter.

## Actions
- `import_drcov` (tool-specific)
- `import_lighthouse` (tool-specific)
- `highlight` (tool-specific)
- `report` (tool-specific)
- `uncovered` (tool-specific)
- `filter` (tool-specific)
- `grep` (host wrapper): run another action, then grep its output lines.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/coverage')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "coverage",
  "arguments": {
    "action": "import_drcov"
  }
}
```
```json
{
  "name": "coverage",
  "arguments": {
    "action": "grep",
    "source_action": "import_drcov",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
