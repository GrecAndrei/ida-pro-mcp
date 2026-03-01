# IDA MCP Tool Doc: `protocol`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `protocol` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

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
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
