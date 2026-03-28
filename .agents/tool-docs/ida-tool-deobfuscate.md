# IDA MCP Tool Doc: `deobfuscate`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `deobfuscate` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Deobfuscation analysis. Compact output per finding. Actions: detect_encoding, xor_scan (auto-decode with single-byte keys), stack_strings (char-by-char construction), opaque_predicates, control_flow_flatten, dead_code, api_hashing, dynamic_dispatch, anti_disasm, decode_attempt (provide key or auto-detect).

## Actions
- `detect_encoding` (tool-specific)
- `xor_scan` (tool-specific)
- `stack_strings` (tool-specific)
- `opaque_predicates` (tool-specific)
- `control_flow_flatten` (tool-specific)
- `dead_code` (tool-specific)
- `api_hashing` (tool-specific)
- `dynamic_dispatch` (tool-specific)
- `anti_disasm` (tool-specific)
- `decode_attempt` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/deobfuscate')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "deobfuscate",
  "arguments": {
    "action": "detect_encoding"
  }
}
```
```json
{
  "name": "deobfuscate",
  "arguments": {
    "action": "grep",
    "source_action": "detect_encoding",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
