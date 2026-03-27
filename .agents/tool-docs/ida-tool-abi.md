# IDA MCP Tool Doc: `abi`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `abi` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
ABI and calling convention analysis. Actions: detect, stack_args, reg_args, return_type, varargs, struct_return, tail_calls, prologue, epilogue, abi_violations.

## Actions
- `detect` (analysis)
- `stack_args` (tool-specific)
- `reg_args` (tool-specific)
- `return_type` (tool-specific)
- `varargs` (tool-specific)
- `struct_return` (tool-specific)
- `tail_calls` (tool-specific)
- `prologue` (tool-specific)
- `epilogue` (tool-specific)
- `abi_violations` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/abi')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "abi",
  "arguments": {
    "action": "detect"
  }
}
```
```json
{
  "name": "abi",
  "arguments": {
    "action": "grep",
    "source_action": "detect",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
