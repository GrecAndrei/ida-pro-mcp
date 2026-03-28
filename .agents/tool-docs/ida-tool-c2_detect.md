# IDA MCP Tool Doc: `c2_detect`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `c2_detect` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
C2/malware behavior detection. Actions: indicators, persistence, evasion, injection, exfiltration, lateral_movement, privilege_escalation, capabilities, config_extract, ioc_extract.

## Actions
- `indicators` (tool-specific)
- `persistence` (tool-specific)
- `evasion` (tool-specific)
- `injection` (tool-specific)
- `exfiltration` (tool-specific)
- `lateral_movement` (tool-specific)
- `privilege_escalation` (tool-specific)
- `capabilities` (tool-specific)
- `config_extract` (tool-specific)
- `ioc_extract` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/c2_detect')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "c2_detect",
  "arguments": {
    "action": "indicators"
  }
}
```
```json
{
  "name": "c2_detect",
  "arguments": {
    "action": "grep",
    "source_action": "indicators",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
