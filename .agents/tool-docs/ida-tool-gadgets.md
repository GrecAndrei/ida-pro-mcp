# IDA MCP Tool Doc: `gadgets`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `gadgets` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
ROP/JOP/COP gadget discovery. Query supports regex. x86/x64 + ARM/AArch64. Actions: rop, jop, cop, syscall, write_what_where, stack_pivot, shellcode_space, mitigations, seh_handlers, pivot_chains.

## Actions
- `rop` (tool-specific)
- `jop` (tool-specific)
- `cop` (tool-specific)
- `syscall` (tool-specific)
- `write_what_where` (tool-specific)
- `stack_pivot` (tool-specific)
- `shellcode_space` (tool-specific)
- `mitigations` (tool-specific)
- `seh_handlers` (tool-specific)
- `pivot_chains` (tool-specific)
- `grep` (host wrapper): run another action, then grep its output lines.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/gadgets')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "gadgets",
  "arguments": {
    "action": "rop"
  }
}
```
```json
{
  "name": "gadgets",
  "arguments": {
    "action": "grep",
    "source_action": "rop",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
