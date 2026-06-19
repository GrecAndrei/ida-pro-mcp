# IDA MCP Tool Doc: `background`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `background` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Background batch execution for long-running analysis tasks and IDAPython scripts. Submit scripts or tool calls to run in background threads without interrupting IDA. Actions: submit, status, cancel, result, list, wait.

## Actions
- `submit` (tool-specific)
- `status` (read/discovery)
- `cancel` (tool-specific)
- `result` (tool-specific)
- `list` (read/discovery)
- `wait` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/background')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- `action`: `string` - allowed: `submit, status, cancel, result, list, wait`
- `script`: `string` - IDAPython script source to run in background
- `session_id`: `string` - IDA session ID to run tool calls within. Task persists with this session.
- `state`: `string` - Filter tasks by state (pending/running/done/failed/cancelled)
- `task_id`: `string` - Batch task identifier returned by submit
- `timeout`: `number` - Max seconds to wait for task completion
- `tool_call`: `object` - Tool call to execute: {'tool': 'session', 'action': 'status', 'args': {...}}
- `action` wrappers accepted by host: `grep, head, tail, pick, next, stats` (in addition to tool-specific enum values above).

## Minimal Call Shapes
```json
{
  "name": "background",
  "arguments": {
    "action": "submit"
  }
}
```
```json
{
  "name": "background",
  "arguments": {
    "action": "grep",
    "source_action": "submit",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
