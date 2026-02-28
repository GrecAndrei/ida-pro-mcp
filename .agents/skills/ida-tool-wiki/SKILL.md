# IDA MCP Tool Skill
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Tool
`wiki`

## Use This Skill When
- You need to call the `wiki` tool.
- You want exact action/parameter contract without scanning global tool metadata.

## Description
Built-in documentation system with ranked search, fuzzy topic resolution, section navigation, related-topic discovery, and generated fallback docs. Actions: list_topics, read, search, sections, index.

## Actions
- `list_topics`
- `read`
- `search`
- `sections`
- `index`

## Parameters
- `action`: `string` - allowed: `list_topics, read, search, sections, index`
- `category`: `string|array`
- `context_lines`: `integer`
- `fuzzy`: `boolean`
- `include_related`: `boolean`
- `include_snippets`: `boolean`
- `limit`: `integer`
- `max_results`: `integer`
- `offset`: `integer`
- `query`: `string`
- `section`: `string`
- `strict_topic`: `boolean`
- `topic`: `string`

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
