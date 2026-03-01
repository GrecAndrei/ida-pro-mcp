# IDA MCP Tool Doc: `wiki`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `wiki` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Built-in documentation system with ranked search, fuzzy topic resolution, section navigation, related-topic discovery, and generated fallback docs. Actions: list_topics, read, search, sections, index.

## Actions
- `list_topics`
- `read`
- `search`
- `sections`
- `index`
- `grep` (host wrapper): run another action, then grep its output lines.

## Parameters
- `action`: `string` - allowed: `list_topics, read, search, sections, index`
- `category`: `string|array`
- `context_lines`: `integer`
- `fuzzy`: `boolean`
- `include_related`: `boolean`
- `include_snippets`: `boolean`
- `limit`: `integer`
- `line_end`: `integer`
- `line_start`: `integer`
- `lines`: `string` - Line selector such as '10-40', '25', '10-', or '-40'.
- `max_results`: `integer`
- `offset`: `integer`
- `query`: `string`
- `section`: `string`
- `strict_topic`: `boolean`
- `topic`: `string`
- `verbose`: `boolean` - Include full structural metadata in wiki responses.

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
