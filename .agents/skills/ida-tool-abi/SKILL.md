# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`abi`

## Use This Skill When
- You need to call the `abi` tool.
- You want exact action/parameter contract without scanning global tool metadata.

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

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
