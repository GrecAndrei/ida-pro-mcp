# IDA MCP Tool Doc: `debug`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `debug` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Debugger control and dynamic analysis. Actions: start, stop, continue, step_into, step_over, run_to, run_until, breakpoints, add_bp, del_bp, enable_bp, regs, set_reg, threads, modules, callstack, read_mem, write_mem.

## Actions
- `start` (tool-specific)
- `stop` (tool-specific)
- `continue` (tool-specific)
- `step_into` (tool-specific)
- `step_over` (tool-specific)
- `run_to` (tool-specific)
- `run_until` (tool-specific)
- `breakpoints` (tool-specific)
- `add_bp` (tool-specific)
- `del_bp` (tool-specific)
- `enable_bp` (tool-specific)
- `regs` (tool-specific)
- `set_reg` (tool-specific)
- `threads` (tool-specific)
- `modules` (tool-specific)
- `callstack` (tool-specific)
- `read_mem` (tool-specific)
- `write_mem` (tool-specific)
- `grep` (host wrapper): run another action, then grep its output lines.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/debug')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "debug",
  "arguments": {
    "action": "start"
  }
}
```
```json
{
  "name": "debug",
  "arguments": {
    "action": "grep",
    "source_action": "start",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
