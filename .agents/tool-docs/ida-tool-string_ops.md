# IDA MCP Tool Doc: `string_ops`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `string_ops` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

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
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- (tool takes action-only or dynamic args)

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
