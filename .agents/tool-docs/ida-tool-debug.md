# IDA MCP Tool Doc: `debug`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `debug` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Debugger control and dynamic analysis. Actions: start, stop, continue, step_into, step_over, run_to, run_until, breakpoints, add_bp, del_bp, enable_bp, regs, set_reg, threads, modules, callstack, read_mem, write_mem.

## Actions
- `start`
- `stop`
- `continue`
- `step_into`
- `step_over`
- `run_to`
- `run_until`
- `breakpoints`
- `add_bp`
- `del_bp`
- `enable_bp`
- `regs`
- `set_reg`
- `threads`
- `modules`
- `callstack`
- `read_mem`
- `write_mem`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
