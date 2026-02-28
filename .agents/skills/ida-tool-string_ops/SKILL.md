# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`string_ops`

## Use This Skill When
- You need to call the `string_ops` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Advanced string analysis. Query supports regex. Actions: decode_all, find_urls, find_paths, find_registry, find_ips, find_emails, find_commands, encoding_stats, multilingual, suspicious.

## Actions
- `decode_all`
- `find_urls`
- `find_paths`
- `find_registry`
- `find_ips`
- `find_emails`
- `find_commands`
- `encoding_stats`
- `multilingual`
- `suspicious`

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
