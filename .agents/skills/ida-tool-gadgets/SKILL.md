# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`gadgets`

## Use This Skill When
- You need to call the `gadgets` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
ROP/JOP/COP gadget discovery. Query supports regex. x86/x64 + ARM/AArch64. Actions: rop, jop, cop, syscall, write_what_where, stack_pivot, shellcode_space, mitigations, seh_handlers, pivot_chains.

## Actions
- `rop`
- `jop`
- `cop`
- `syscall`
- `write_what_where`
- `stack_pivot`
- `shellcode_space`
- `mitigations`
- `seh_handlers`
- `pivot_chains`

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
