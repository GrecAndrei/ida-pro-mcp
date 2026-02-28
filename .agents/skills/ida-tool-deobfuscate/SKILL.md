# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`deobfuscate`

## Use This Skill When
- You need to call the `deobfuscate` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Deobfuscation analysis. Compact output per finding. Actions: detect_encoding, xor_scan (auto-decode with single-byte keys), stack_strings (char-by-char construction), opaque_predicates, control_flow_flatten, dead_code, api_hashing, dynamic_dispatch, anti_disasm, decode_attempt (provide key or auto-detect).

## Actions
- `detect_encoding`
- `xor_scan`
- `stack_strings`
- `opaque_predicates`
- `control_flow_flatten`
- `dead_code`
- `api_hashing`
- `dynamic_dispatch`
- `anti_disasm`
- `decode_attempt`

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
