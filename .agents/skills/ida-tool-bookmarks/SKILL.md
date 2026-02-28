# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`bookmarks`

## Use This Skill When
- You need to call the `bookmarks` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Enhanced session-correlated bookmarking. Actions: add, list, delete, update, clear, find (supports regex/glob/substring in name, notes, tags, addr, category), export.

## Actions
- `add`
- `list`
- `delete`
- `update`
- `clear`
- `find`
- `export`

## Parameters
- `action`: `string` - allowed: `add, list, delete, update, clear, find, export`
- `addr`: `string`
- `category`: `string`
- `id`: `integer`
- `name`: `string`
- `notes`: `string`
- `priority`: `integer`
- `query`: `string`
- `tags`: `array|string`

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
