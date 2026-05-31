# IDA MCP Tool Doc: `governance`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `governance` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Pre-flight validation for edits: detect contradictions, PII, dangerous patches. Actions: check, redact, list_rules, stats.

## Actions
- `check` (tool-specific)
- `redact` (tool-specific)
- `list_rules` (tool-specific)
- `stats` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/governance')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed: `check, redact, list_rules, stats`
- `addr`: `string` - Target address for the operation
- `context`: `object` - Optional context dict for governance check
- `metadata`: `object` - Optional metadata dict for governance check
- `operation_type`: `string` - Operation type for check: patch, comment, rename, type_change, execution, annotation
- `proposed_value`: `string` - The proposed value to check or redact
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "governance",
  "arguments": {
    "action": "check"
  }
}
```
```json
{
  "name": "governance",
  "arguments": {
    "action": "grep",
    "source_action": "check",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
