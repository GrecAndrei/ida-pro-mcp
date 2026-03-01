# IDA MCP Tool Doc: `c2_detect`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `c2_detect` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
C2/malware behavior detection. Actions: indicators, persistence, evasion, injection, exfiltration, lateral_movement, privilege_escalation, capabilities, config_extract, ioc_extract.

## Actions
- `indicators`
- `persistence`
- `evasion`
- `injection`
- `exfiltration`
- `lateral_movement`
- `privilege_escalation`
- `capabilities`
- `config_extract`
- `ioc_extract`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
