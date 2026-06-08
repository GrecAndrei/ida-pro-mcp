# IDA MCP Tool Doc: `survey`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `survey` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Context-aware reverse-engineering survey queue for variable-renaming follow-up and differential decomp feedback. list/status expose the current scoped backlog, delay defers a survey until other addresses are visited, and submit applies renames/findings then records the resolved experience. Actions: list, status, delay, submit.

## Actions
- `list` (read/discovery)
- `status` (read/discovery)
- `delay` (tool-specific)
- `submit` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/survey')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed: `list, status, delay, submit`
- `addr`: `string` - Address of the function or offset related to the survey
- `blackboard_publish`: `array` - List of findings to publish to blackboard (action=submit)
- `bookmark`: `string` - Bookmark tag name to apply to the function (action=submit)
- `delay_until_any`: `array` - List of addresses the LLM wants to check first (action=delay)
- `reason`: `string` - Reason for delaying the survey (action=delay)
- `renames`: `object` - Map of generic variable names to new names (action=submit)
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "survey",
  "arguments": {
    "action": "list"
  }
}
```
```json
{
  "name": "survey",
  "arguments": {
    "action": "grep",
    "source_action": "list",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
