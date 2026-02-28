# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`c2_detect`

## Use This Skill When
- You need to call the `c2_detect` tool.
- You want exact action/parameter contract without scanning global tool metadata.

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

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
