# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`protocol`

## Use This Skill When
- You need to call the `protocol` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Network protocol analysis. Query supports regex. Actions: detect, parsers, serializers, handlers, endpoints, tls_config, socket_flow, packet_struct, magic_numbers, state_machine.

## Actions
- `detect`
- `parsers`
- `serializers`
- `handlers`
- `endpoints`
- `tls_config`
- `socket_flow`
- `packet_struct`
- `magic_numbers`
- `state_machine`

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
