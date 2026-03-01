# IDA MCP Tool Doc: `abi`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `abi` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
ABI and calling convention analysis. Actions: detect, stack_args, reg_args, return_type, varargs, struct_return, tail_calls, prologue, epilogue, abi_violations.

## Actions
- `detect`
- `stack_args`
- `reg_args`
- `return_type`
- `varargs`
- `struct_return`
- `tail_calls`
- `prologue`
- `epilogue`
- `abi_violations`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
