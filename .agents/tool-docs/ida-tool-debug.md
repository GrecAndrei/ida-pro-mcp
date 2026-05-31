# IDA MCP Tool Doc: `debug`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `debug` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Control the debugger: run, step, breakpoints, registers, memory, threads. Actions: status, start, stop, continue, step_into, step_over, run_to, run_until, breakpoints, add_bp, del_bp, enable_bp, add_hw_bp, add_watch, regs, set_reg, reg_diff, snapshot_regs, threads, modules, callstack, read_mem, write_mem, search_mem, stack_dump, mem_map, bp_context, trace_start, trace_stop, trace_read, mem_diff.

## Actions
- `status` (read/discovery)
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
- `add_hw_bp` (tool-specific)
- `add_watch` (tool-specific)
- `regs` (tool-specific)
- `set_reg` (tool-specific)
- `reg_diff` (tool-specific)
- `snapshot_regs` (tool-specific)
- `threads` (tool-specific)
- `modules` (tool-specific)
- `callstack` (tool-specific)
- `read_mem` (tool-specific)
- `write_mem` (tool-specific)
- `search_mem` (tool-specific)
- `stack_dump` (tool-specific)
- `mem_map` (tool-specific)
- `bp_context` (tool-specific)
- `trace_start` (tool-specific)
- `trace_stop` (tool-specific)
- `trace_read` (tool-specific)
- `mem_diff` (tool-specific)
- `read` (read/discovery)
- `write` (write/mutate)
- `rw` (tool-specific)
- `execute` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

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
    "action": "status"
  }
}
```
```json
{
  "name": "debug",
  "arguments": {
    "action": "grep",
    "source_action": "status",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
